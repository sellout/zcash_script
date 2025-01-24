use std::collections::VecDeque;
use std::slice::Iter;

use ripemd::Ripemd160;
use secp256k1::ecdsa;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::external::pubkey::PubKey;
use super::opcode::{Control::*, Normal::*, *};
use super::script::*;
use super::script_error::*;
use super::scriptnum::*;

/// The ways in which a transparent input may commit to the transparent outputs of its
/// transaction.
///
/// Note that:
/// - Transparent inputs always commit to all shielded outputs.
/// - Shielded inputs always commit to all outputs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignedOutputs {
    /// The input signature commits to all transparent outputs in the transaction.
    All,
    /// The transparent input's signature commits to the transparent output at the same
    /// index as the transparent input.
    ///
    /// If the specified transparent output along with any shielded outputs only consume
    /// part of this input, anyone is permitted to modify the transaction to claim the
    /// remainder.
    Single,
    /// The transparent input's signature does not commit to any transparent outputs.
    ///
    /// If the shielded outputs only consume part (or none) of this input, anyone is
    /// permitted to modify the transaction to claim the remainder.
    None,
}

/// The different SigHash types, as defined in <https://zips.z.cash/zip-0143>
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HashType {
    pub signed_outputs: SignedOutputs,
    /// Allows anyone to add transparent inputs to this transaction.
    pub anyone_can_pay: bool,
}

impl HashType {
    /// Construct a `HashType` from bit flags.
    ///
    /// ## Consensus rules
    ///
    /// [§4.10](https://zips.z.cash/protocol/protocol.pdf#sighash):
    /// - Any `HashType` in a v5 transaction must have no undefined bits set.
    pub fn from_bits(bits: i32, is_strict: bool) -> Result<Self, InvalidHashType> {
        let unknown_bits = (bits | 0x83) ^ 0x83;
        if is_strict && unknown_bits != 0 {
            Err(InvalidHashType::ExtraBitsSet(unknown_bits))
        } else {
            let msigned_outputs = match (bits & 2 != 0, bits & 1 != 0) {
                (false, false) => Err(InvalidHashType::UnknownSignedOutputs),
                (false, true) => Ok(SignedOutputs::All),
                (true, false) => Ok(SignedOutputs::None),
                (true, true) => Ok(SignedOutputs::Single),
            };
            msigned_outputs.map(|signed_outputs| HashType {
                signed_outputs,
                anyone_can_pay: bits & 0x80 != 0,
            })
        }
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    /// Script verification flags
    pub struct VerificationFlags: u32 {
        /// Evaluate P2SH subscripts (softfork safe,
        /// [BIP16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki).
        const P2SH = 1 << 0;

        /// Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
        /// Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
        /// (softfork safe, but not used or intended as a consensus rule).
        const StrictEnc = 1 << 1;

        /// Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
        /// (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 5).
        const LowS = 1 << 3;

        /// verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 7).
        const NullDummy = 1 << 4;

        /// Using a non-push operator in the scriptSig causes script failure (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 2).
        const SigPushOnly = 1 << 5;

        /// Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
        /// pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
        /// any other push causes the script to fail ([BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 3).
        /// In addition, whenever a stack element is interpreted as a number, it must be of minimal length ([BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 4).
        /// (softfork safe)
        const MinimalData = 1 << 6;

        /// Discourage use of NOPs reserved for upgrades (NOP1-10)
        ///
        /// Provided so that nodes can avoid accepting or mining transactions
        /// containing executed NOP's whose meaning may change after a soft-fork,
        /// thus rendering the script invalid; with this flag set executing
        /// discouraged NOPs fails the script. This verification flag will never be
        /// a mandatory flag applied to scripts in a block. NOPs that are not
        /// executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
        const DiscourageUpgradableNOPs = 1 << 7;

        /// Require that only a single stack element remains after evaluation. This changes the success criterion from
        /// "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
        /// "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
        /// (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 6)
        /// Note: CLEANSTACK should never be used without P2SH.
        const CleanStack = 1 << 8;

        /// Verify CHECKLOCKTIMEVERIFY
        ///
        /// See [BIP65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki) for details.
        const CHECKLOCKTIMEVERIFY = 1 << 9;
    }
}

pub trait SignatureChecker {
    fn check_sig(
        &self,
        _script_sig: &Signature,
        _vch_pub_key: &[u8],
        _script_code: &Script,
    ) -> bool {
        false
    }

    fn check_lock_time(&self, _lock_time: &ScriptNum) -> bool {
        false
    }
}

pub struct BaseSignatureChecker();

impl SignatureChecker for BaseSignatureChecker {}

pub struct CallbackTransactionSignatureChecker<'a> {
    pub sighash: SighashCalculator<'a>,
    pub lock_time: &'a ScriptNum,
    pub is_final: bool,
}

type ValType = Vec<u8>;

fn cast_to_bool(vch: &ValType) -> bool {
    for i in 0..vch.len() {
        if vch[i] != 0 {
            // Can be negative zero
            if i == vch.len() - 1 && vch[i] == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stack<T>(Vec<T>);

fn catch_underflow<U>(opt: Option<U>) -> Result<U, ScriptError> {
    opt.ok_or(ScriptError::InvalidStackOperation)
}

/// Wraps a Vec (or whatever underlying implementation we choose in a way that matches the C++ impl
/// and provides us some decent chaining)
impl<T: Clone> Stack<T> {
    fn rindex(&self, i: usize) -> Result<usize, ScriptError> {
        let len = self.0.len();
        if i < len {
            Ok(len - i - 1)
        } else {
            Err(ScriptError::InvalidStackOperation)
        }
    }

    pub fn rget(&self, i: usize) -> Result<&T, ScriptError> {
        self.rindex(i)
            .and_then(|idx| catch_underflow(self.0.get(idx)))
    }

    pub fn push_dup(&mut self, i: usize) -> Result<(), ScriptError> {
        self.rget(i).cloned().map(|elem| self.push(elem))
    }

    pub fn swap(&mut self, a: usize, b: usize) -> Result<(), ScriptError> {
        if self.len() <= a || self.len() <= b {
            Err(ScriptError::InvalidStackOperation)
        } else {
            Ok(self.0.swap(a, b))
        }
    }

    pub fn pop(&mut self) -> Result<T, ScriptError> {
        catch_underflow(self.0.pop())
    }

    pub fn push(&mut self, value: T) {
        self.0.push(value)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> Iter<'_, T> {
        self.0.iter()
    }

    pub fn last(&self) -> Result<&T, ScriptError> {
        catch_underflow(self.0.last())
    }

    pub fn split_last(&self) -> Result<(&T, Stack<T>), ScriptError> {
        catch_underflow(self.0.split_last()).map(|(last, rem)| (last, Stack(rem.to_vec())))
    }

    pub fn erase(&mut self, start: usize, end: Option<usize>) -> Result<(), ScriptError> {
        self.rindex(start).map(|idx| {
            for _ in 0..end.map_or(1, |e| start - e) {
                self.0.remove(idx);
            }
        })
    }

    pub fn insert(&mut self, i: usize, element: T) -> Result<(), ScriptError> {
        self.rindex(i).map(|idx| self.0.insert(idx, element))
    }
}

fn is_compressed_or_uncompressed_pub_key(vch_pub_key: &[u8]) -> bool {
    match vch_pub_key[0] {
        0x02 | 0x03 => vch_pub_key.len() == PubKey::COMPRESSED_PUBLIC_KEY_SIZE,
        0x04 => vch_pub_key.len() == PubKey::PUBLIC_KEY_SIZE,
        _ => false, // not a public key
    }
}

#[derive(Clone)]
pub struct Signature {
    sig: ecdsa::Signature,
    sighash: HashType,
}

fn decode_signature(vch_sig_in: &[u8], is_strict: bool) -> Result<Option<Signature>, ScriptError> {
    match vch_sig_in.split_last() {
        // Empty signature. Not strictly DER encoded, but allowed to provide a compact way to
        // provide an invalid signature for use with CHECK(MULTI)SIG
        None => Ok(None),
        Some((hash_type, vch_sig)) => Ok(Some(Signature {
            sig: ecdsa::Signature::from_der(vch_sig).map_err(ScriptError::SigDER)?,
            sighash: HashType::from_bits((*hash_type).into(), is_strict)
                .map_err(ScriptError::SigHashType)?,
        })),
    }
}

fn check_signature_encoding(
    vch_sig: &[u8],
    flags: VerificationFlags,
) -> Result<Option<Signature>, ScriptError> {
    decode_signature(vch_sig, flags.contains(VerificationFlags::StrictEnc)).and_then(
        |sig| match sig {
            None => Ok(None),
            Some(sig0) => {
                if flags.contains(VerificationFlags::LowS) && !PubKey::check_low_s(&sig0.sig) {
                    Err(ScriptError::SigHighS)
                } else {
                    Ok(Some(sig0))
                }
            }
        },
    )
}

fn check_pub_key_encoding(vch_sig: &[u8], flags: VerificationFlags) -> Result<(), ScriptError> {
    if flags.contains(VerificationFlags::StrictEnc)
        && !is_compressed_or_uncompressed_pub_key(vch_sig)
    {
        return Err(ScriptError::PubKeyType);
    };
    Ok(())
}

fn is_sig_valid(
    vch_sig: &[u8],
    vch_pub_key: &[u8],
    flags: VerificationFlags,
    script: &Script<'_>,
    checker: &dyn SignatureChecker,
) -> Result<bool, ScriptError> {
    let sig = check_signature_encoding(vch_sig, flags)?;
    check_pub_key_encoding(vch_pub_key, flags).map(|()| {
        sig.map(|sig0| checker.check_sig(&sig0, &vch_pub_key, script))
            .unwrap_or(false)
    })
}

const BN_ZERO: ScriptNum = ScriptNum(0);
const BN_ONE: ScriptNum = ScriptNum(1);
const VCH_FALSE: ValType = Vec::new();
const VCH_TRUE: [u8; 1] = [1];

fn cast_from_bool(b: bool) -> ValType {
    if b {
        VCH_TRUE.to_vec()
    } else {
        VCH_FALSE
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    stack: Stack<Vec<u8>>,
    altstack: Stack<Vec<u8>>,
    // We keep track of how many operations have executed so far to prevent expensive-to-verify
    // scripts
    op_count: u8,
    // This keeps track of the conditional flags at each nesting level during execution. If we're in
    // a branch of execution where *any* of these conditionals are false, we ignore opcodes unless
    // those opcodes direct control flow (OP_IF, OP_ELSE, etc.).
    vexec: Stack<bool>,
}

impl State {
    pub fn initial(stack: Stack<Vec<u8>>) -> Self {
        State {
            stack,
            altstack: Stack(vec![]),
            op_count: 0,
            vexec: Stack(vec![]),
        }
    }
}

fn unop<T: Clone>(
    stack: &mut Stack<T>,
    op: impl Fn(T) -> Result<T, ScriptError>,
) -> Result<(), ScriptError> {
    let item = stack.pop()?;
    op(item).map(|res| stack.push(res))
}

fn binop<T: Clone>(
    stack: &mut Stack<T>,
    op: impl Fn(T, T) -> Result<T, ScriptError>,
) -> Result<(), ScriptError> {
    let x2 = stack.pop()?;
    let x1 = stack.pop()?;
    op(x1, x2).map(|res| stack.push(res))
}

/// Run a single step of the interpreter.
///
/// This is useful for testing & debugging, as we can set up the exact state we want in order to
/// trigger some behavior.
pub fn eval_step(
    pc: &mut &[u8],
    script: &Script,
    flags: VerificationFlags,
    checker: &impl SignatureChecker,
    state: &mut State,
) -> Result<(), ScriptError> {
    //
    // Read instruction
    //
    Script::get_op(pc).and_then(|opcode| {
        opcode.map_or(
            if should_exec(&state.vexec) {
                Err(ScriptError::BadOpcode(None))
            } else {
                Ok(())
            },
            |opcode| eval_opcode(flags, opcode, script, checker, state),
        )
    })
}

fn eval_opcode(
    flags: VerificationFlags,
    opcode: Opcode,
    script: &Script,
    checker: &dyn SignatureChecker,
    state: &mut State,
) -> Result<(), ScriptError> {
    let stack = &mut state.stack;
    let op_count = &mut state.op_count;
    let vexec = &mut state.vexec;
    let altstack = &mut state.altstack;

    (match opcode {
        Opcode::PushValue(pv) => {
            if pv.value().map_or(0, |v| v.len()) <= MAX_SCRIPT_ELEMENT_SIZE {
                if should_exec(vexec) {
                    eval_push_value(&pv, flags.contains(VerificationFlags::MinimalData), stack)
                } else {
                    Ok(())
                }
            } else {
                Err(ScriptError::PushSize(None))
            }
        }
        Opcode::Operation(op) => {
            // Note how OP_RESERVED does not count towards the opcode limit.
            *op_count += 1;
            if *op_count <= 201 {
                match op {
                    Operation::Control(control) => eval_control(control, stack, vexec),
                    Operation::Disabled(op) => Err(ScriptError::DisabledOpcode(op.into())),
                    Operation::Normal(normal) => {
                        if should_exec(vexec) {
                            eval_operation(
                                normal, flags, script, checker, stack, altstack, op_count,
                            )
                        } else {
                            Ok(())
                        }
                    }
                }
            } else {
                Err(ScriptError::OpCount)
            }
        }
    })
    .and_then(|()| {
        // Size limits
        if stack.len() + altstack.len() > 1000 {
            Err(ScriptError::StackSize(None))
        } else {
            Ok(())
        }
    })
}

fn eval_push_value(
    pv: &PushValue,
    require_minimal: bool,
    stack: &mut Stack<Vec<u8>>,
) -> Result<(), ScriptError> {
    if require_minimal && !pv.is_minimal_push() {
        Err(ScriptError::MinimalData)
    } else {
        pv.value()
            .map_or(Err(ScriptError::BadOpcode(None)), |v| Ok(stack.push(v)))
    }
}

// Are we in an executing branch of the script?
fn should_exec(vexec: &Stack<bool>) -> bool {
    vexec.iter().all(|value| *value)
}

/// <expression> if [statements] [else [statements]] endif
fn eval_control(
    control: Control,
    stack: &mut Stack<Vec<u8>>,
    vexec: &mut Stack<bool>,
) -> Result<(), ScriptError> {
    match control {
        OP_IF | OP_NOTIF => Ok(vexec.push(if should_exec(vexec) {
            let vch = stack
                .pop()
                .map_err(|_| ScriptError::UnbalancedConditional)?;
            let value = cast_to_bool(&vch);
            if control == OP_NOTIF {
                !value
            } else {
                value
            }
        } else {
            false
        })),

        OP_ELSE => vexec
            .pop()
            .map_err(|_| ScriptError::UnbalancedConditional)
            .map(|last| vexec.push(!last)),

        OP_ENDIF => vexec
            .pop()
            .map_err(|_| ScriptError::UnbalancedConditional)
            .map(|_| ()),

        OP_VERIF | OP_VERNOTIF => Err(ScriptError::BadOpcode(Some(control.into()))),
    }
}
fn eval_operation(
    op: Normal,
    flags: VerificationFlags,
    script: &Script,
    checker: &dyn SignatureChecker,
    stack: &mut Stack<Vec<u8>>,
    altstack: &mut Stack<Vec<u8>>,
    op_count: &mut u8,
) -> Result<(), ScriptError> {
    let require_minimal = flags.contains(VerificationFlags::MinimalData);

    let unop_num = |stackin: &mut Stack<Vec<u8>>,
                    op: &dyn Fn(ScriptNum) -> ScriptNum|
     -> Result<(), ScriptError> {
        unop(stackin, |vch| {
            ScriptNum::new(&vch, require_minimal, None)
                .map_err(ScriptError::ScriptNumError)
                .map(|bn| op(bn).getvch())
        })
    };

    let binop_num = |stack: &mut Stack<Vec<u8>>,
                     op: &dyn Fn(ScriptNum, ScriptNum) -> Vec<u8>|
     -> Result<(), ScriptError> {
        binop(stack, |x1, x2| {
            let bn2 =
                ScriptNum::new(&x2, require_minimal, None).map_err(ScriptError::ScriptNumError)?;
            let bn1 =
                ScriptNum::new(&x1, require_minimal, None).map_err(ScriptError::ScriptNumError)?;
            Ok(op(bn1, bn2))
        })
    };

    let magma =
        |stack: &mut Stack<Vec<u8>>,
         op: &dyn Fn(ScriptNum, ScriptNum) -> ScriptNum|
         -> Result<(), ScriptError> { binop_num(stack, &|bn1, bn2| op(bn1, bn2).getvch()) };

    let binrel = |stack: &mut Stack<Vec<u8>>,
                  op: &dyn Fn(ScriptNum, ScriptNum) -> bool|
     -> Result<(), ScriptError> {
        binop_num(stack, &|bn1, bn2| cast_from_bool(op(bn1, bn2)))
    };

    match op {
        //
        // Control
        //
        OP_NOP => Ok(()),

        OP_CHECKLOCKTIMEVERIFY => {
            // This was originally OP_NOP2 but has been repurposed
            // for OP_CHECKLOCKTIMEVERIFY. So, we should act based
            // on whether or not CLTV has been activated in a soft
            // fork.
            if !flags.contains(VerificationFlags::CHECKLOCKTIMEVERIFY) {
                if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                    Err(ScriptError::DiscourageUpgradableNOPs)
                } else {
                    Ok(())
                }
            } else {
                // Note that elsewhere numeric opcodes are limited to
                // operands in the range -2**31+1 to 2**31-1, however it is
                // legal for opcodes to produce results exceeding that
                // range. This limitation is implemented by `ScriptNum`'s
                // default 4-byte limit.
                //
                // If we kept to that limit we'd have a year 2038 problem,
                // even though the `lock_time` field in transactions
                // themselves is u32 which only becomes meaningless
                // after the year 2106.
                //
                // Thus as a special case we tell `ScriptNum` to accept up
                // to 5-byte bignums, which are good until 2**39-1, well
                // beyond the 2**32-1 limit of the `lock_time` field itself.
                let lock_time = ScriptNum::new(stack.rget(0)?, require_minimal, Some(5))
                    .map_err(ScriptError::ScriptNumError)?;

                // In the rare event that the argument may be < 0 due to
                // some arithmetic being done first, you can always use
                // 0 MAX CHECKLOCKTIMEVERIFY.
                if lock_time < ScriptNum(0) {
                    return Err(ScriptError::NegativeLockTime);
                }

                // Actually compare the specified lock time with the transaction.
                if checker.check_lock_time(&lock_time) {
                    Ok(())
                } else {
                    Err(ScriptError::UnsatisfiedLockTime)
                }
            }
        }

        OP_NOP1 | OP_NOP3 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9
        | OP_NOP10 => {
            // Do nothing, though if the caller wants to prevent people from using
            // these NOPs (as part of a standard tx rule, for example) they can
            // enable `DiscourageUpgradableNOPs` to turn these opcodes into errors.
            if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                Err(ScriptError::DiscourageUpgradableNOPs)
            } else {
                Ok(())
            }
        }

        // (true -- ) or
        // (false -- false) and return
        OP_VERIFY => stack.pop().and_then(|vch| {
            if cast_to_bool(&vch) {
                Ok(())
            } else {
                Err(ScriptError::Verify)
            }
        }),

        OP_RETURN => Err(ScriptError::OpReturn),

        //
        // Stack ops
        //
        OP_TOALTSTACK => stack.pop().map(|vch| altstack.push(vch)),

        OP_FROMALTSTACK => altstack
            .pop()
            .map_err(|_| ScriptError::InvalidAltstackOperation)
            .map(|vch| stack.push(vch)),

        // (x1 x2 --)
        OP_2DROP => stack.pop().and_then(|_| stack.pop()).map(|_| ()),

        // (x1 x2 -- x1 x2 x1 x2)
        OP_2DUP => stack.push_dup(1).and_then(|_| stack.push_dup(1)),

        // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
        OP_3DUP => stack
            .push_dup(2)
            .and_then(|_| stack.push_dup(2))
            .and_then(|_| stack.push_dup(2)),

        // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
        OP_2OVER => stack.push_dup(3).and_then(|_| stack.push_dup(3)),

        // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
        OP_2ROT => stack.rget(4).cloned().and_then(|vch2| {
            stack
                .rget(5)
                .cloned()
                .and_then(|vch1| stack.erase(6, Some(4)).map(|()| stack.push(vch1)))
                .map(|()| stack.push(vch2))
        }),

        // (x1 x2 x3 x4 -- x3 x4 x1 x2)
        OP_2SWAP => stack.swap(3, 1).and_then(|()| stack.swap(2, 0)),

        // (x - 0 | x x)
        OP_IFDUP => {
            let vch = stack.rget(0)?;
            Ok(if cast_to_bool(vch) {
                stack.push(vch.clone())
            })
        }

        // -- stacksize
        OP_DEPTH => i64::try_from(stack.len())
            .map_err(|err| ScriptError::StackSize(Some(err)))
            .map(|bn| stack.push(ScriptNum(bn).getvch())),

        // (x -- )
        OP_DROP => stack.pop().map(|_| ()),

        // (x -- x x)
        OP_DUP => stack.push_dup(0),

        // (x1 x2 -- x2)
        OP_NIP => stack.erase(2, None),

        // (x1 x2 -- x1 x2 x1)
        OP_OVER => stack.push_dup(1),

        // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
        // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
        OP_PICK | OP_ROLL => stack
            .pop()
            .and_then(|vch| {
                ScriptNum::new(&vch, require_minimal, None).map_err(ScriptError::ScriptNumError)
            })
            .and_then(|num| {
                usize::try_from(num.getint()).map_err(|_| ScriptError::InvalidStackOperation)
            })
            .and_then(|n| {
                stack.rget(n).cloned().and_then(|vch| {
                    if op == OP_ROLL {
                        stack.erase(n, None)?;
                    }
                    Ok(stack.push(vch))
                })
            }),

        // (x1 x2 x3 -- x2 x3 x1)
        //  x2 x1 x3  after first swap
        //  x2 x3 x1  after second swap
        OP_ROT => stack.swap(2, 1).and_then(|()| stack.swap(1, 0)),

        // (x1 x2 -- x2 x1)
        OP_SWAP => stack.swap(1, 0),

        // (x1 x2 -- x2 x1 x2)
        OP_TUCK => stack.rget(0).cloned().and_then(|vch| stack.insert(2, vch)),

        // (in -- in size)
        OP_SIZE => stack
            .rget(0)?
            .len()
            .try_into()
            .map_err(|err| ScriptError::PushSize(Some(err)))
            .map(|n| stack.push(ScriptNum(n).getvch())),

        //
        // Bitwise logic
        //

        // (x1 x2 - bool)
        OP_EQUAL => binop(stack, &|x1, x2| Ok(cast_from_bool(x1 == x2))),
        // (x1 x2 - bool)
        OP_EQUALVERIFY => stack.pop().and_then(|vch2| {
            stack.pop().and_then(|vch1| {
                if vch1 == vch2 {
                    Ok(())
                } else {
                    Err(ScriptError::EqualVerify)
                }
            })
        }),

        //
        // Numeric
        //
        OP_1ADD => unop_num(stack, &|x| x + BN_ONE),
        OP_1SUB => unop_num(stack, &|x| x - BN_ONE),
        OP_NEGATE => unop_num(stack, &|x| -x),
        OP_ABS => unop_num(stack, &|x| if x < BN_ZERO { -x } else { x }),
        OP_NOT => unop_num(stack, &|x| ScriptNum((x == BN_ZERO).into())),
        OP_0NOTEQUAL => unop_num(stack, &|x| ScriptNum((x != BN_ZERO).into())),

        // (x1 x2 -- out)
        OP_ADD => magma(stack, &|x1, x2| x1 + x2),
        OP_SUB => magma(stack, &|x1, x2| x1 - x2),
        OP_BOOLAND => binrel(stack, &|x1, x2| x1 != BN_ZERO && x2 != BN_ZERO),
        OP_BOOLOR => binrel(stack, &|x1, x2| x1 != BN_ZERO || x2 != BN_ZERO),
        OP_NUMEQUAL => binrel(stack, &|x1, x2| x1 == x2),
        OP_NUMEQUALVERIFY => {
            let x2 = stack.pop()?;
            let x1 = stack.pop()?;
            ScriptNum::new(&x1, require_minimal, None)
                .map_err(ScriptError::ScriptNumError)
                .and_then(|bn1| {
                    ScriptNum::new(&x2, require_minimal, None)
                        .map_err(ScriptError::ScriptNumError)
                        .and_then(|bn2| {
                            if bn1 == bn2 {
                                Ok(())
                            } else {
                                Err(ScriptError::NumEqualVerify)
                            }
                        })
                })
        }
        OP_NUMNOTEQUAL => binrel(stack, &|x1, x2| x1 != x2),
        OP_LESSTHAN => binrel(stack, &|x1, x2| x1 < x2),
        OP_GREATERTHAN => binrel(stack, &|x1, x2| x1 > x2),
        OP_LESSTHANOREQUAL => binrel(stack, &|x1, x2| x1 <= x2),
        OP_GREATERTHANOREQUAL => binrel(stack, &|x1, x2| x1 >= x2),
        OP_MIN => magma(stack, &|x1, x2| {
            if x1 < x2 {
                x1
            } else {
                x2
            }
        }),
        OP_MAX => magma(stack, &|x1, x2| {
            if x1 > x2 {
                x1
            } else {
                x2
            }
        }),

        // (x min max -- out)
        OP_WITHIN => stack.pop().and_then(|x3| {
            stack.pop().and_then(|x2| {
                stack.pop().and_then(|x1| {
                    ScriptNum::new(&x1, require_minimal, None)
                        .and_then(|bn1| {
                            ScriptNum::new(&x2, require_minimal, None).and_then(|bn2| {
                                ScriptNum::new(&x3, require_minimal, None)
                                    .map(|bn3| stack.push(cast_from_bool(bn2 <= bn1 && bn1 < bn3)))
                            })
                        })
                        .map_err(ScriptError::ScriptNumError)
                })
            })
        }),

        //
        // Crypto
        //
        OP_RIPEMD160 => unop(stack, &|hash| Ok(Ripemd160::digest(hash).to_vec())),
        OP_SHA1 => unop(stack, &|hash| {
            let mut hasher = Sha1::new();
            hasher.update(hash);
            Ok(hasher.finalize().to_vec())
        }),
        OP_SHA256 => unop(stack, &|hash| Ok(Sha256::digest(hash).to_vec())),
        OP_HASH160 => unop(stack, &|hash| {
            Ok(Ripemd160::digest(Sha256::digest(hash)).to_vec())
        }),
        OP_HASH256 => unop(stack, &|hash| {
            Ok(Sha256::digest(Sha256::digest(hash)).to_vec())
        }),

        // (sig pubkey -- bool)
        OP_CHECKSIG | OP_CHECKSIGVERIFY => {
            let vch_pub_key = &stack.pop()?;
            let vch_sig = &stack.pop()?;
            let success = is_sig_valid(&vch_sig, &vch_pub_key, flags, script, checker)?;
            if op == OP_CHECKSIGVERIFY {
                if success {
                    Ok(())
                } else {
                    Err(ScriptError::CheckSigVerify)
                }
            } else {
                Ok(stack.push(cast_from_bool(success)))
            }
        }

        // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
        OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
            let keys_count = stack
                .pop()
                .and_then(|vch| {
                    ScriptNum::new(&vch, require_minimal, None).map_err(ScriptError::ScriptNumError)
                })
                .and_then(|bn| {
                    u8::try_from(bn.getint()).map_err(|err| ScriptError::PubKeyCount(Some(err)))
                })?;
            if keys_count > 20 {
                return Err(ScriptError::PubKeyCount(None));
            };
            *op_count += keys_count;
            if *op_count > 201 {
                return Err(ScriptError::OpCount);
            };

            let mut keys = VecDeque::with_capacity(keys_count.into());
            for _ in 0..keys_count {
                stack.pop().map(|key| keys.push_back(key))?;
            }

            let sigs_count = stack
                .pop()
                .and_then(|vch| {
                    ScriptNum::new(&vch, require_minimal, None).map_err(ScriptError::ScriptNumError)
                })
                .and_then(|bn| {
                    usize::try_from(bn.getint()).map_err(|err| ScriptError::SigCount(Some(err)))
                })?;
            if sigs_count > keys_count.into() {
                Err(ScriptError::SigCount(None))
            } else {
                // Note how this makes the exact order of pubkey/signature evaluation
                // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set. See the
                // script_(in)valid tests for details.
                let success = (0..sigs_count).rfold(Ok(true), |acc, i| {
                    acc.and_then(|prev| {
                        stack.pop().and_then(|sig| {
                            if prev {
                                while let Some(key) = keys.pop_front() {
                                    if is_sig_valid(&sig, &key, flags, script, checker)? {
                                        return Ok(true);
                                    } else if keys.len() < i {
                                        // If there are more signatures left than keys left, then
                                        // too many signatures have failed. Exit early, without
                                        // checking any further signatures.
                                        return Ok(false);
                                    }
                                }
                                Ok(false)
                            } else {
                                Ok(false)
                            }
                        })
                    })
                })?;

                // A bug causes CHECKMULTISIG to consume one extra argument whose contents were not
                // checked in any way.
                //
                // Unfortunately this is a potential source of mutability, so optionally verify it
                // is exactly equal to zero prior to removing it from the stack.
                if !stack.pop()?.is_empty() && flags.contains(VerificationFlags::NullDummy) {
                    Err(ScriptError::SigNullDummy)
                } else if op == OP_CHECKMULTISIGVERIFY {
                    if success {
                        Ok(())
                    } else {
                        Err(ScriptError::CheckMultisigVerify)
                    }
                } else {
                    Ok(stack.push(cast_from_bool(success)))
                }
            }
        }

        _ => Err(ScriptError::BadOpcode(Some(op.into()))),
    }
}

pub fn eval_step2<'a>(
    flags: VerificationFlags,
    checker: &'a impl SignatureChecker,
) -> impl Fn(&mut &[u8], &Script, &mut State, &mut ()) -> Result<(), ScriptError> + 'a {
    move |pc, script: &Script, state, _payload| eval_step(pc, script, flags, checker, state)
}

pub fn eval_script<T>(
    stack: Stack<Vec<u8>>,
    script: &Script,
    payload: &mut T,
    eval_step: &impl Fn(&mut &[u8], &Script, &mut State, &mut T) -> Result<(), ScriptError>,
) -> Result<Stack<Vec<u8>>, ScriptError> {
    // There's a limit on how large scripts can be.
    if script.0.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }

    let mut pc = script.0;

    let mut state = State::initial(stack);

    // Main execution loop
    //
    // TODO: With a streaming lexer, this could be
    //
    // lex(script).fold(eval_step, State::initial(stack))
    while !pc.is_empty() {
        eval_step(&mut pc, script, &mut state, payload)?;
    }

    if !state.vexec.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }

    Ok(state.stack)
}

/// All signature hashes are 32 bytes, since they are either:
/// - a SHA-256 output (for v1 or v2 transactions).
/// - a BLAKE2b-256 output (for v3 and above transactions).
pub const SIGHASH_SIZE: usize = 32;

/// A function which is called to obtain the sighash.
///    - script_code: the scriptCode being validated. Note that this not always
///      matches script_sig, i.e. for P2SH.
///    - hash_type: the hash type being used.
///
/// The `extern "C"` function that calls this doesn’t give much opportunity for rich failure
/// reporting, but returning `None` indicates _some_ failure to produce the desired hash.
pub type SighashCalculator<'a> = &'a dyn Fn(&[u8], HashType) -> Option<[u8; SIGHASH_SIZE]>;

impl CallbackTransactionSignatureChecker<'_> {
    pub fn verify_signature(
        sig: &ecdsa::Signature,
        pubkey: &PubKey,
        sighash: &[u8; SIGHASH_SIZE],
    ) -> bool {
        pubkey.verify(sighash, sig)
    }
}

impl SignatureChecker for CallbackTransactionSignatureChecker<'_> {
    fn check_sig(&self, sig: &Signature, vch_pub_key: &[u8], script_code: &Script) -> bool {
        let pubkey = PubKey(vch_pub_key);

        pubkey.is_valid()
            && (self.sighash)(script_code.0, sig.sighash)
                .map(|sighash| Self::verify_signature(&sig.sig, &pubkey, &sighash))
                .unwrap_or(false)
    }

    fn check_lock_time(&self, lock_time: &ScriptNum) -> bool {
        // There are two times of nLockTime: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nLockTime < LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if *self.lock_time < LOCKTIME_THRESHOLD && *lock_time >= LOCKTIME_THRESHOLD
            || *self.lock_time >= LOCKTIME_THRESHOLD && *lock_time < LOCKTIME_THRESHOLD
            // Now that we know we're comparing apples-to-apples, the
            // comparison is a simple numeric one.
            || lock_time > self.lock_time
        {
            false
            // Finally the nLockTime feature can be disabled and thus
            // CHECKLOCKTIMEVERIFY bypassed if every txin has been
            // finalized by setting nSequence to maxint. The
            // transaction would be allowed into the blockchain, making
            // the opcode ineffective.
            //
            // Testing if this vin is not final is sufficient to
            // prevent this condition. Alternatively we could test all
            // inputs, but testing just this input minimizes the data
            // required to prove correct CHECKLOCKTIMEVERIFY execution.
        } else {
            !self.is_final
        }
    }
}

pub fn verify_script<T>(
    script_sig: &Script,
    script_pub_key: &Script,
    flags: VerificationFlags,
    payload: &mut T,
    stepper: &impl Fn(&mut &[u8], &Script, &mut State, &mut T) -> Result<(), ScriptError>,
) -> Result<(), ScriptError> {
    if flags.contains(VerificationFlags::SigPushOnly) && !script_sig.is_push_only() {
        Err(ScriptError::SigPushOnly)
    } else {
        let data_stack = eval_script(Stack(Vec::new()), script_sig, payload, stepper)?;
        let pub_key_stack = eval_script(data_stack.clone(), script_pub_key, payload, stepper)?;
        if pub_key_stack.last().map_or(false, cast_to_bool) {
            // Additional validation for spend-to-script-hash transactions:
            let result_stack = if flags.contains(VerificationFlags::P2SH)
                && script_pub_key.is_pay_to_script_hash()
            {
                // script_sig must be literals-only or validation fails
                if script_sig.is_push_only() {
                    data_stack
                        // stack cannot be empty here, because if it was the P2SH HASH <> EQUAL
                        // scriptPubKey would be evaluated with an empty stack and the `eval_script`
                        // above would return false.
                        .split_last()
                        .and_then(|(pub_key_2, remaining_stack)| {
                            eval_script(remaining_stack, &Script(pub_key_2), payload, stepper)
                        })
                        .and_then(|p2sh_stack| {
                            if p2sh_stack.last().map_or(false, cast_to_bool) {
                                Ok(p2sh_stack)
                            } else {
                                Err(ScriptError::EvalFalse)
                            }
                        })
                } else {
                    Err(ScriptError::SigPushOnly)
                }?
            } else {
                pub_key_stack
            };

            // The CLEANSTACK check is only performed after potential P2SH evaluation,
            // as the non-P2SH evaluation of a P2SH script will obviously not result in
            // a clean stack (the P2SH inputs remain).
            if flags.contains(VerificationFlags::CleanStack) {
                // Disallow CLEANSTACK without P2SH, as otherwise a switch
                // CLEANSTACK->P2SH+CLEANSTACK would be possible, which is not a softfork (and P2SH
                // should be one).
                assert!(flags.contains(VerificationFlags::P2SH));
                if result_stack.len() != 1 {
                    return Err(ScriptError::CleanStack);
                }
            }

            Ok(())
        } else {
            Err(ScriptError::EvalFalse)
        }
    }
}
