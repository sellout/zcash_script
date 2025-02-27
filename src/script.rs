use serde::{Deserialize, Serialize};

use super::opcode::{LargeValue::*, Normal::*, SmallValue::*, *};
use super::script_error::*;
use super::scriptnum::*;
use crate::interpreter::*;

/// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: usize = 10_000;

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: ScriptNum = ScriptNum(500_000_000); // Tue Nov  5 00:53:20 1985 UTC

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AndMaybe<T, U> {
    Only(T),
    Indeed(T, U),
}

impl<T, U> AndMaybe<T, U> {
    /// Get the ever-present `T` out of the structure.
    pub fn fst(&self) -> &T {
        match self {
            AndMaybe::Only(t) => t,
            AndMaybe::Indeed(t, _) => t,
        }
    }

    /// Get the `U` out of the structure, if there is one.
    pub fn snd(&self) -> Option<&U> {
        match self {
            AndMaybe::Only(_) => None,
            AndMaybe::Indeed(_, u) => Some(u),
        }
    }

    pub fn bimap<T2, U2>(&self, f: impl Fn(&T) -> T2, g: impl Fn(&U) -> U2) -> AndMaybe<T2, U2> {
        match self {
            AndMaybe::Only(t) => AndMaybe::Only(f(t)),
            AndMaybe::Indeed(t, u) => AndMaybe::Indeed(f(t), g(u)),
        }
    }
}

impl<T: Default, U> AndMaybe<T, U> {
    /// Applicative
    pub fn pure(u: U) -> Self {
        AndMaybe::Indeed(T::default(), u)
    }
}

impl<T, U> AndMaybe<T, U> {
    /// This will produce [`Indeed`] only if every element of the array is [`Indeed`], otherwise it
    /// produces an array of [`Only`] the first values.
    pub fn sequence(xs: &[Self]) -> AndMaybe<Vec<&T>, Vec<&U>> {
        let ts = xs.iter().map(|x| x.fst()).collect();

        for x in xs.iter() {
            match x {
                AndMaybe::Only(_) => return AndMaybe::Only(ts),
                AndMaybe::Indeed(_, _) => (),
            }
        }

        AndMaybe::Indeed(
            ts,
            xs.iter()
                .map(|x| x.snd().expect("the whole array is `Indeed`"))
                .collect(),
        )
    }
}

/// This can be specialized in one of two ways:
/// - with `T` ~ [`PushValue`], this creates a [`ScriptSig`] for a new output; and
/// - with `T` ~ [`Opcode`], this reads a [`ScriptSig`] from an input on the chain.
///
/// This is because script_sigs are now required to be push-only, but if we’re spending a pre-v5
/// output, it’s possible that it contains some operations.
///
/// If we didn’t need to allow non-push-only script_sigs, then this could simply be an ailas for
/// [`Vec<PushValue>`], but as it’s not, we need to support the older style as well.
///
/// FIXME: Delete this if there are none already on the chain, since a new one can never be
///        created.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ScriptSig<T>(Vec<T>);

/// Returns a pre-v5 script_sig, and also a v5+ script_sig, if possible.
pub fn script_sigs_from_bytes(
    bytes: &[u8],
) -> Result<AndMaybe<ScriptSig<Opcode>, ScriptSig<PushValue>>, ScriptError> {
    let mut result = Vec::with_capacity(bytes.len());
    deserialize_vec(&mut result, bytes)?;
    Ok(AndMaybe::sequence(
        &result
            .iter()
            .map(|op| match op {
                Opcode::PushValue(pv) => AndMaybe::Indeed(op.clone(), pv.clone()),
                Opcode::Operation(_) => AndMaybe::Only(op.clone()),
            })
            .collect::<Vec<AndMaybe<Opcode, PushValue>>>(),
    )
    .bimap(
        |ts| ScriptSig(ts.iter().map(|x| (*x).clone()).collect()),
        |us| ScriptSig(us.iter().map(|x| (*x).clone()).collect()),
    ))
}

impl<T: Evaluable> ScriptSig<T> {
    pub fn eval<P>(
        &self,
        stack: Stack<Vec<u8>>,
        script_code: &[u8],
        payload: &mut P,
        eval_step: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), ScriptError>,
    ) -> Result<Stack<Vec<u8>>, ScriptError> {
        // There's a limit on how large scripts can be.
        if self.0.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptSize);
        }

        // Main execution loop
        //
        // TODO: With a streaming lexer, this could be
        //
        // lex(script).fold(eval_step, State::initial(stack))
        let mut state = State::initial(stack);
        self.0.iter().fold(Ok(&mut state), |state, opcode| {
            state.and_then(|state| eval_step(opcode, script_code, state, payload).map(|()| state))
        })?;

        if !state.vexec.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        Ok(state.stack)
    }
}

impl ScriptSig<PushValue> {
    /// Create a new v5-compatible script_sig.
    ///
    /// If you need a pre-v5 script_sig, it can only be instantiated using
    /// [`Serializable::from_bytes`], as we should no longer have _new_ pre-v5 script_sigs, but are
    /// only reading them off earlier parts of the chain.
    pub fn new(script_sig: Vec<PushValue>) -> Self {
        ScriptSig(script_sig)
    }
}

impl<T: Serializable> Serializable for ScriptSig<T> {
    fn to_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .fold(Vec::new(), |acc, op| [acc, op.to_bytes()].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), ScriptError> {
        let mut result = Vec::with_capacity(bytes.len());
        deserialize_vec(&mut result, bytes).map(|()| (ScriptSig(result), &[][..]))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ScriptPubKey(pub Vec<Opcode>);

impl ScriptPubKey {
    /** Encode/decode small integers: */
    fn decode_op_n(opcode: SmallValue) -> u32 {
        if opcode == OP_0 {
            return 0;
        }
        assert!(OP_1 <= opcode && opcode <= OP_16);
        (u8::from(opcode) - (u8::from(OP_1) - 1)).into()
    }

    /// Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    /// as 20 sigops. With pay-to-script-hash, that changed:
    /// CHECKMULTISIGs serialized in script_sigs are
    /// counted more accurately, assuming they are of the form
    ///  ... OP_N CHECKMULTISIG ...
    pub fn get_sig_op_count(&self, accurate: bool) -> u32 {
        self.0
            .iter()
            .fold((0, None), |(n, last_opcode), opcode| {
                (
                    if let Opcode::Operation(Operation::Normal(op)) = opcode {
                        if *op == OP_CHECKSIG || *op == OP_CHECKSIGVERIFY {
                            n + 1
                        } else if *op == OP_CHECKMULTISIG || *op == OP_CHECKMULTISIGVERIFY {
                            match last_opcode {
                                Some(&Opcode::PushValue(PushValue::SmallValue(pv))) => {
                                    if accurate && OP_1 <= pv && pv <= OP_16 {
                                        n + Self::decode_op_n(pv)
                                    } else {
                                        n + 20
                                    }
                                }
                                _ => n + 20,
                            }
                        } else {
                            n
                        }
                    } else {
                        n
                    },
                    Some(opcode),
                )
            })
            .0
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        match &(self.0)[..] {
            [Opcode::Operation(Operation::Normal(OP_HASH160)), Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))), Opcode::Operation(Operation::Normal(OP_EQUAL))] => {
                v.len() == 0x14
            }
            _ => false,
        }
    }

    pub fn eval<P>(
        &self,
        stack: Stack<Vec<u8>>,
        script_code: &[u8],
        payload: &mut P,
        eval_step: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), ScriptError>,
    ) -> Result<Stack<Vec<u8>>, ScriptError> {
        // There's a limit on how large scripts can be.
        if self.0.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptSize);
        }

        // Main execution loop
        //
        // TODO: With a streaming lexer, this could be
        //
        // lex(script).fold(eval_step, State::initial(stack))
        let mut state = State::initial(stack);
        self.0.iter().fold(Ok(&mut state), |state, opcode| {
            state.and_then(|state| eval_step(opcode, script_code, state, payload).map(|()| state))
        })?;

        if !state.vexec.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        Ok(state.stack)
    }
}

impl Serializable for ScriptPubKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .fold(Vec::new(), |acc, op| [acc, op.to_bytes()].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), ScriptError> {
        let mut result = Vec::with_capacity(bytes.len());
        deserialize_vec(&mut result, bytes).map(|()| (ScriptPubKey(result), &[][..]))
    }
}

/// A Zcash script consists of both the script_sig and the script_pubkey.
///
/// See the documentation on [`ScriptSig`] for explanation of `T`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script<T> {
    pub sig: ScriptSig<T>,
    pub pub_key: ScriptPubKey,
}

impl<T: Evaluable> Script<T> {
    /// The primary script evaluator.
    ///
    /// **NB**: This takes an extra `p2sh` function argument. The behavior of P2SH scripts depends
    ///         on the specific `T`, so those specializations provide that argument and are the
    ///         functions that should be called.
    fn eval_<P>(
        &self,
        flags: VerificationFlags,
        script_code: &[u8],
        payload: &mut P,
        stepper: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), ScriptError>,
        p2sh: impl Fn(&Stack<Vec<u8>>, &mut P) -> Result<Stack<Vec<u8>>, ScriptError>,
    ) -> Result<(), ScriptError> {
        let data_stack = self.sig.eval(Stack::new(), &[], payload, stepper)?;
        let pub_key_stack =
            self.pub_key
                .eval(data_stack.clone(), &script_code, payload, stepper)?;
        if pub_key_stack.last().map_or(false, cast_to_bool) {
            // Additional validation for spend-to-script-hash transactions:
            let result_stack = if flags.contains(VerificationFlags::P2SH)
                && self.pub_key.is_pay_to_script_hash()
            {
                p2sh(&data_stack, payload)?
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

impl Script<Opcode> {
    pub fn eval<P>(
        &self,
        flags: VerificationFlags,
        script_code: &[u8],
        payload: &mut P,
        stepper: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), ScriptError>,
    ) -> Result<(), ScriptError> {
        self.eval_(flags, script_code, payload, stepper, |_, _| {
            Err(ScriptError::SigPushOnly)
        })
    }
}

impl Script<PushValue> {
    pub fn eval<P>(
        &self,
        flags: VerificationFlags,
        script_code: &[u8],
        payload: &mut P,
        stepper: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), ScriptError>,
    ) -> Result<(), ScriptError> {
        self.eval_(
            flags,
            script_code,
            payload,
            stepper,
            |data_stack, payload| {
                data_stack
                    // stack cannot be empty here, because if it was the P2SH HASH <> EQUAL
                    // scriptPubKey would be evaluated with an empty stack and the
                    // `pub_key.eval` above would return false.
                    .split_last()
                    .and_then(|(pub_key_2, remaining_stack)| {
                        ScriptPubKey::from_bytes(pub_key_2).and_then(|(pk2, _)| {
                            pk2.eval(remaining_stack, pub_key_2, payload, stepper)
                        })
                    })
                    .and_then(|p2sh_stack| {
                        if p2sh_stack.last().map_or(false, cast_to_bool) {
                            Ok(p2sh_stack)
                        } else {
                            Err(ScriptError::EvalFalse)
                        }
                    })
            },
        )
    }
}

/// This populates the provided `Vec`.
fn deserialize_vec<T: Serializable>(init: &mut Vec<T>, bytes: &[u8]) -> Result<(), ScriptError> {
    if bytes.is_empty() {
        Ok(())
    } else {
        T::from_bytes(bytes).and_then(|(op, rest)| {
            init.push(op);
            deserialize_vec(init, rest)
        })
    }
}
