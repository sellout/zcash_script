//! Managing sequences of opcodes.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write;

use thiserror::Error;

use crate::{
    interpreter,
    op::{self},
    opcode::{self, push_value::LargeValue::*, Operation::*, PossiblyBad, PushValue},
    signature, Opcode,
};

pub(crate) mod iter;

/// Errors that can occur during script verification.
#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Error {
    // Max sizes
    #[error(
        "Script size{} exceeded maxmimum ({} bytes)",
        .0.map_or("", |size| " ({size} bytes)"),
        Code::MAX_SIZE
    )]
    ScriptSize(Option<usize>),

    #[error("during parsing: {0}")]
    Opcode(opcode::Error),

    #[error("non-push opcode encountered in script sig when push-only required")]
    SigPushOnly,

    /// __TODO__: Remove the [`Option`] around [`opcode::PossiblyBad`] when C++ support is removed.
    #[error("during interpretation: {1}")]
    Interpreter(Option<opcode::PossiblyBad>, interpreter::Error),

    /// A error external to the script validation code. This can come from the stepper.
    ///
    /// __TODO__: Replace the `str` with a type parameter, which will be `Void` in validation code,
    /// but can be different in the steppers.
    #[error("external error: {0}")]
    ExternalError(&'static str),

    #[error("{} closed before the end of the script", match .0 { 1 => "1 conditional opcode wasn’t", n => "{n} conditional opcodes weren’t"})]
    UnclosedConditional(usize),

    #[error("the script is P2SH, but there was no redeem script left on the stack")]
    MissingRedeemScript,

    #[error("clean stack requirement not met")]
    CleanStack,
}

impl Error {
    /// This case is only generated in comparisons. It merges the `interpreter::Error::OpCount` case
    /// with the `opcode::Error::DisabledOpcode` case. This is because there is an edge case when
    /// there is a disabled opcode as the `MAX_OP_COUNT + 1` operation (not opcode) in a script. In
    /// this case, the C++ implementation checks the op_count first, while the Rust implementation
    /// fails on disabled opcodes as soon as they’re read (since the script is guaranteed to fail if
    /// they occur, even in an inactive branch). To allow comparison tests to pass (especially
    /// property & fuzz tests), we need these two failure cases to be seen as identical.
    pub const AMBIGUOUS_COUNT_DISABLED: Self =
        Self::ExternalError("ambiguous OpCount or DisabledOpcode error");

    /// This case is only generated in comparisons. It merges `Self::ScriptNumError` and
    /// `Self::SigHighS`, which can only come from the Rust implementation, with
    /// `ScriptError_t_SCRIPT_ERR_UNKNOWN_ERROR`, which can only come from the C++ implementation,
    /// but in at least all of the cases that either of the Rust error cases would happen.
    pub const AMBIGUOUS_UNKNOWN_NUM_HIGHS: Self =
        Self::ExternalError("ambiguous Unknown, or ScriptNum, or HighS error");

    /// Convert errors that don’t exist in the C++ code into the cases that do.
    pub fn normalize(&self) -> Self {
        match self {
            Self::ScriptSize(Some(_)) => Self::ScriptSize(None),
            Self::Opcode(oerr) => match oerr {
                opcode::Error::Read { .. } => {
                    Self::Interpreter(None, interpreter::Error::BadOpcode)
                }
                opcode::Error::Disabled(_) => Self::AMBIGUOUS_COUNT_DISABLED,
                opcode::Error::PushSize(Some(_)) => Self::from(opcode::Error::PushSize(None)),
                _ => self.clone(),
            },
            Self::Interpreter(
                Some(opcode::PossiblyBad::Good(op::IF | op::NOTIF)),
                interpreter::Error::InvalidStackOperation(_),
            ) => Self::Interpreter(None, interpreter::Error::UnbalancedConditional),
            Self::Interpreter(
                Some(opcode::PossiblyBad::Good(op::FROMALTSTACK)),
                interpreter::Error::InvalidStackOperation(_),
            ) => Self::Interpreter(
                Some(opcode::PossiblyBad::Good(op::FROMALTSTACK)),
                interpreter::Error::InvalidStackOperation(None),
            ),
            Self::Interpreter(_, ierr) => match ierr {
                interpreter::Error::OpCount => Self::AMBIGUOUS_COUNT_DISABLED,
                interpreter::Error::SignatureEncoding(signature::Error::SigHighS) => {
                    Self::AMBIGUOUS_UNKNOWN_NUM_HIGHS
                }
                interpreter::Error::Num(_) => Self::AMBIGUOUS_UNKNOWN_NUM_HIGHS,
                interpreter::Error::Verify => self.clone(),
                _ => Self::Interpreter(None, ierr.normalize()),
            },
            Self::UnclosedConditional(_) => {
                Self::Interpreter(None, interpreter::Error::UnbalancedConditional)
            }
            Self::MissingRedeemScript => {
                Self::Interpreter(None, interpreter::Error::InvalidStackOperation(None))
            }
            _ => self.clone(),
        }
    }
}

impl From<opcode::Error> for Error {
    fn from(value: opcode::Error) -> Self {
        Error::Opcode(value)
    }
}

type AnnOpcode = Result<Opcode, Vec<Error>>;

/// Evaluation functions for script components.
pub trait Evaluable {
    /// Get the byte length of this script sig.
    fn byte_len(&self) -> usize;

    /// Convert a sequence of `Opcode`s to the bytes that would be included in a transaction.
    fn to_bytes(&self) -> Vec<u8>;

    /// Evaluate this script component.
    fn eval(
        &self,
        flags: interpreter::Flags,
        checker: &dyn interpreter::SignatureChecker,
        stack: interpreter::Stack<Vec<u8>>,
    ) -> Result<interpreter::Stack<Vec<u8>>, Error>;

    /// Returns true iff this script is P2SH.
    fn is_pay_to_script_hash(&self) -> bool;

    /// Called by `IsStandardTx` and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    fn is_push_only(&self) -> bool;
}

/// Type that has a "asm" representation.
pub trait Asm {
    /// Return the "asm" representation of this type.
    ///
    /// The `attempt_sighash_decode` flag indicates whether to attempt to parse
    /// [`signature::Decoded`] objects from data within the script that matches the format
    /// of a signature. Only set this to `true` for scripts you believe could contain
    /// signatures (e.g. [`Sig`]). This flag does nothing if the `signature-validation`
    /// feature flag is disabled.
    fn to_asm(&self, attempt_sighash_decode: bool) -> String;
}

/// A script component is used as either the script sig or script pubkey in a script. Depending on
/// `T` (which generally needs an `opcode::Evaluable` instance), it has different properties:
///
/// - `PossiblyBad` – used for scripts that need to go through consensus-compatible verification
///   (that is, read from the chain)
/// - `Opcode` – used for script pubkey and non-push-only script sigs that are authored to be placed
///   on the chain
/// - `PushValue` – used for push-only script sigs that are authored to be placed on the chain
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component<T>(pub Vec<T>);

/// A script sig has only `PushValue` elements.
pub type Sig = Component<PushValue>;

/// A script pubkey has any `Opcode`.
pub type PubKey = Component<Opcode>;

/// A redeem script has any `Opcode`.
pub type Redeem = Component<Opcode>;

/// A script component (sig or pubkey) that came from the chain.
///
/// This is used to preserve particular bits that authored scripts don’t allow.
///
/// **NB**: `Code(script_bytes).to_component().map_err(Error::Opcode).and_then(Component::eval))`
///         has the same _semantics_ as `Code(script_bytes).eval(_)`, but it won’t have the same
///         error message because `to_component` will return a parse error anywhere in the script
///         before `Component::eval` is called, while `Code::eval` interleaves the parsing and
///         evaluation, like the C++ implementation.
///
/// Unlike `Raw`, this allows the chain data to be combined with authored data in, for example,
/// `Script<opcode::PushValue, opcode::PossiblyBad>`, which can then be evaluated holistically.
pub type FromChain = Component<opcode::PossiblyBad>;

impl<T: Clone> Component<T> {
    /// Convert a `Component` to a less restricted opcode type, infallibly.
    pub fn weaken<U: From<T>>(&self) -> Component<U> {
        Component(self.0.iter().cloned().map(|op| U::from(op)).collect())
    }
}

impl<T: opcode::Evaluable> Component<T> {
    /// This parses an entire script.
    ///
    /// **NB**: If `T` is not `opcode::PossiblyBad`, this is stricter than the incremental parsing
    ///         that is done during `verify_script`, because it fails on unknown opcodes no matter
    ///         where they occur (when normally they only fail if they would be evaluated).
    pub fn parse(raw_script: &Code) -> Result<Self, Error> {
        raw_script
            .parse()
            .map(|mpb| mpb.map_err(Error::Opcode).and_then(T::restrict))
            .collect::<Result<_, _>>()
            .map(Component)
    }
}

impl<T: Into<opcode::PossiblyBad> + Clone> Component<T> {
    /// Convert a `Component` to a more restricted opcode type, erroring if it’s not
    /// possible.
    pub fn refine<U: opcode::Evaluable>(&self) -> Result<Component<U>, Error> {
        self.0
            .iter()
            .cloned()
            .map(|op| U::restrict(op.into()))
            .collect::<Result<_, _>>()
            .map(Component)
    }
}

impl<T: Into<opcode::PossiblyBad> + opcode::Evaluable + Clone> Evaluable for Component<T> {
    fn byte_len(&self) -> usize {
        self.0.iter().map(T::byte_len).sum()
    }

    /// Convert a sequence of `Opcode`s to the bytes that would be included in a transaction.
    fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|elem| elem.to_bytes()).collect()
    }

    fn eval(
        &self,
        flags: interpreter::Flags,
        checker: &dyn interpreter::SignatureChecker,
        stack: interpreter::Stack<Vec<u8>>,
    ) -> Result<interpreter::Stack<Vec<u8>>, Error> {
        // There's a limit on how large scripts can be.
        match self.byte_len() {
            ..=Code::MAX_SIZE => iter::eval(
                self.0.iter().cloned().map(Ok),
                flags,
                &Code(self.to_bytes()),
                stack,
                checker,
            ),
            n => Err(Error::ScriptSize(Some(n))),
        }
    }

    /// Returns true iff this script is P2SH.
    fn is_pay_to_script_hash(&self) -> bool {
        match &self
            .0
            .iter()
            .map(|op| op.clone().into())
            .collect::<Vec<_>>()[..]
        {
            [opcode::PossiblyBad::Good(Opcode::Operation(OP_HASH160)), opcode::PossiblyBad::Good(Opcode::PushValue(PushValue::LargeValue(
                PushdataBytelength(v),
            ))), opcode::PossiblyBad::Good(Opcode::Operation(OP_EQUAL))] => v.len() == 0x14,
            _ => false,
        }
    }

    /// Called by `IsStandardTx` and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    fn is_push_only(&self) -> bool {
        self.0.iter().all(|op| {
            matches!(
                op.extract_push_value(),
                Ok(_)
                    | Err(
                        // NB: The C++ impl only checks the push size during interpretation, so
                        // we need to pass this check for too-big `PushValue`s.
                        Error::Opcode(opcode::Error::PushSize(_))
                            | Error::Interpreter(
                                Some(opcode::PossiblyBad::Bad(opcode::Bad::OP_RESERVED)),
                                interpreter::Error::BadOpcode
                            )
                    )
            )
        })
    }
}

impl<T: Asm> Asm for Component<T> {
    fn to_asm(&self, attempt_sighash_decode: bool) -> String {
        self.0
            .iter()
            .map(|op| op.to_asm(attempt_sighash_decode))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// An iterator that provides `Opcode`s from a byte stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Parser<'a>(&'a [u8]);

impl Iterator for Parser<'_> {
    type Item = Result<opcode::PossiblyBad, opcode::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            let (res, rem) = opcode::PossiblyBad::parse(self.0);
            self.0 = rem;
            Some(res)
        }
    }
}

/// When an entire [`crate::Script`] is validated, this is used to tag errors with which component
/// they came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComponentType {
    /// The script sig.
    Sig,
    /// The script pubkey.
    PubKey,
    /// The redeem script from a P2SH script.
    Redeem,
}

/// Serialized script, used inside transaction inputs and outputs
#[derive(Clone, Debug)]
pub struct Code(pub Vec<u8>);

impl Code {
    /// Maximum script length in bytes
    pub(crate) const MAX_SIZE: usize = 10_000;

    /// Produce an [`Opcode`] iterator from [`Code`].
    pub fn parse(&self) -> Parser<'_> {
        Parser(&self.0)
    }

    /// Returns a script annotated with errors that could occur during evaluation.
    pub fn annotate(&self, flags: &interpreter::Flags) -> Vec<AnnOpcode> {
        self.parse()
            .map(|mpb| {
                mpb.map_err(|e| vec![Error::Opcode(e)]).and_then(|pb| {
                    pb.analyze(flags)
                        .map_err(|ierrs| {
                            ierrs
                                .into_iter()
                                .map(|ie| Error::Interpreter(Some(pb.clone()), ie))
                                .collect()
                        })
                        .cloned()
                })
            })
            .collect::<Vec<_>>()
    }

    /// Convert this into a `Component`, which can then be combined in authored scripts in `Script`.
    pub fn to_component(&self) -> Result<Component<opcode::PossiblyBad>, opcode::Error> {
        self.parse().collect::<Result<_, _>>().map(Component)
    }

    /// Convert a sequence of `Opcode`s to the bytes that would be included in a transaction.
    pub fn serialize(script: &[Opcode]) -> Vec<u8> {
        script.iter().flat_map(Vec::from).collect()
    }

    /// Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    /// as 20 sigops. With pay-to-script-hash, that changed:
    /// CHECKMULTISIGs serialized in script_sigs are
    /// counted more accurately, assuming they are of the form
    ///  ... OP_N CHECKMULTISIG ...
    pub fn sig_op_count(&self, accurate: bool) -> u32 {
        iter::sig_op_count(self.parse(), accurate)
    }

    /// Returns whether the script is guaranteed to fail at execution,
    /// regardless of the initial stack.
    ///
    /// The only purpose of this function is to reproduce the behavior of the
    /// zcashd function `IsUnspendable()`, which is used for "asm" encoding
    /// and dust transaction filtering.
    /// <https://github.com/zcash/zcash/blob/2352fbc1ed650ac4369006bea11f7f20ee046b84/src/script/script.h#L617-L620>
    pub fn is_unspendable(&self) -> bool {
        self.parse().next() == Some(Ok(opcode::PossiblyBad::Good(op::RETURN)))
            || self.0.len() > Self::MAX_SIZE
    }
}

impl Evaluable for Code {
    /// Get the byte length of this script sig.
    fn byte_len(&self) -> usize {
        self.0.len()
    }

    /// Convert a sequence of `Opcode`s to the bytes that would be included in a transaction.
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn eval(
        &self,
        flags: interpreter::Flags,
        checker: &dyn interpreter::SignatureChecker,
        stack: interpreter::Stack<Vec<u8>>,
    ) -> Result<interpreter::Stack<Vec<u8>>, Error> {
        match self.byte_len() {
            ..=Code::MAX_SIZE => iter::eval(
                self.parse().map(|res| res.map_err(Error::Opcode)),
                flags,
                self,
                stack,
                checker,
            ),
            n => Err(Error::ScriptSize(Some(n))),
        }
    }

    /// Returns true iff this script is P2SH.
    fn is_pay_to_script_hash(&self) -> bool {
        self.parse()
            .collect::<Result<Vec<_>, _>>()
            .is_ok_and(|ops| Component(ops).is_pay_to_script_hash())
    }

    /// Called by `IsStandardTx` and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    fn is_push_only(&self) -> bool {
        self.parse().all(|op| {
            matches!(
                op,
                // NB: The C++ impl only checks the push size during interpretation, so we need to
                //     pass this check for too-big `PushValue`s.
                Err(opcode::Error::PushSize(_))
                    | Ok(opcode::PossiblyBad::Good(Opcode::PushValue(_))
                        | opcode::PossiblyBad::Bad(opcode::Bad::OP_RESERVED))
            )
        })
    }
}

impl Asm for Code {
    /// Like zcashd’s `ScriptToAsmStr`, this names every opcode it reads, including ones that fail
    /// if evaluated, and prints pushes of any size. It ends with `[error]` only at a push that runs
    /// past the end of the script.
    fn to_asm(&self, attempt_sighash_decode: bool) -> String {
        let attempt_sighash_decode = attempt_sighash_decode && !self.is_unspendable();
        let mut v = Vec::new();
        let mut script = &self.0[..];
        while !script.is_empty() {
            let (r, remainder) = PossiblyBad::parse(script);
            let read = &script[..script.len() - remainder.len()];
            script = remainder;
            v.push(match r {
                Ok(PossiblyBad::Good(op)) => op.to_asm(attempt_sighash_decode),
                Ok(PossiblyBad::Bad(op)) => op.to_asm(false),
                Err(opcode::Error::Disabled(Some(op))) => op.to_asm(false),
                // A push of more than 520 bytes can’t be evaluated, but it is printed as hex like
                // any other push of more than 4 bytes. It can’t be a signature, so there is no
                // sighash type to decode.
                Err(opcode::Error::PushSize(Some(len))) => {
                    read[read.len() - len..]
                        .iter()
                        .fold(String::new(), |mut hex, byte| {
                            write!(hex, "{byte:02x}").expect("writing to a `String` can’t fail");
                            hex
                        })
                }
                // A truncated push consumes the rest of the script.
                Err(_) => "[error]".to_string(),
            });
        }
        v.join(" ")
    }
}

impl core::fmt::Display for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_asm(false))
    }
}

/// A script represented by two byte sequences – one is the sig, the other is the pubkey.
pub struct Raw {
    /// The script signature from the spending transaction.
    pub sig: Code,
    /// The script pubkey from the funding transaction.
    pub pub_key: Code,
}

impl Raw {
    /// Create a [`Raw`] script from the slices extracted from transactions.
    pub fn from_raw_parts(sig: Vec<u8>, pub_key: Vec<u8>) -> Self {
        Raw {
            sig: Code(sig),
            pub_key: Code(pub_key),
        }
    }

    /// Apply a function to both components of a script, returning the tuple of results.
    pub(crate) fn map<T>(&self, f: impl Fn(&Code) -> T) -> (T, T) {
        (f(&self.sig), f(&self.pub_key))
    }

    /// Returns a script annotated with errors that could occur during evaluation.
    pub fn annotate(&self, flags: &interpreter::Flags) -> (Vec<AnnOpcode>, Vec<AnnOpcode>) {
        self.map(|c| c.annotate(flags))
    }

    /// Validate a [`Raw`] script.
    pub fn eval(
        &self,
        flags: interpreter::Flags,
        checker: &dyn interpreter::SignatureChecker,
    ) -> Result<bool, (ComponentType, Error)> {
        iter::eval_script(&self.sig, &self.pub_key, flags, checker)
    }
}

impl Asm for Raw {
    fn to_asm(&self, attempt_sighash_decode: bool) -> String {
        self.sig.to_asm(attempt_sighash_decode) + " " + &self.pub_key.to_asm(false)
    }
}

impl core::fmt::Display for Raw {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_asm(true))
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};

    use super::{Asm, Code};

    /// The expected strings are what zcashd’s `ScriptToAsmStr` produces.
    #[test]
    fn to_asm_matches_zcashd_on_opcodes_that_fail() {
        let asm = |bytes: &[u8]| Code(bytes.to_vec()).to_asm(false);
        assert_eq!(asm(&[0x50, 0x51]), "OP_RESERVED 1");
        assert_eq!(asm(&[0x62, 0x65, 0x66]), "OP_VER OP_VERIF OP_VERNOTIF");
        assert_eq!(
            asm(&[0x51, 0x89, 0x8a, 0x51]),
            "1 OP_RESERVED1 OP_RESERVED2 1"
        );
        assert_eq!(asm(&[0x7e, 0x51]), "OP_CAT 1");
        assert_eq!(asm(&[0xab, 0x51]), "OP_CODESEPARATOR 1");
        assert_eq!(asm(&[0xba, 0xfe, 0x51]), "OP_UNKNOWN OP_UNKNOWN 1");
        assert_eq!(asm(&[0xff]), "OP_INVALIDOPCODE");

        // A push of more than 520 bytes prints as hex.
        let oversized: Vec<u8> = [&[0x4d, 0x09, 0x02][..], &[0xab; 521], &[0x51]].concat();
        assert_eq!(
            asm(&oversized),
            ["ab".repeat(521), String::from(" 1")].concat()
        );

        // Only a truncated push ends the output.
        assert_eq!(asm(&[0x51, 0x02, 0x01]), "1 [error]");
        assert_eq!(asm(&[0x7e, 0x4d, 0x09]), "OP_CAT [error]");
    }

    /// zcashd prints a signature as it was pushed, followed by its sighash type.
    #[cfg(feature = "signature-validation")]
    #[test]
    fn to_asm_prints_signatures_as_pushed() {
        // A strict-DER signature whose R is 2^256 - 1, which is larger than the group order, so
        // secp256k1 parses it as 0 and would re-encode it as `020100`.
        let sig: Vec<u8> = [
            &[0x30, 0x26, 0x02, 0x21, 0x00][..],
            &[0xff; 32],
            &[0x02, 0x01, 0x01],
        ]
        .concat();
        let push = [&[0x29][..], &sig, &[0x01]].concat();
        assert_eq!(Code(push).to_asm(true), hex::encode(&sig) + "[ALL]");
    }
}
