use serde::{Deserialize, Serialize};

use crate::interpreter::*;
use crate::script_error::*;
pub use operation::*;
pub use push_value::*;

mod operation;
mod push_value;

/** Script opcodes */
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum Opcode {
    /// - only type allowed in v5+ script_sigs
    /// - don’t count toward `op_count`
    PushValue(PushValue),
    /// - represented by a single byte
    /// - count toward `op_count``
    Operation(Operation),
}

impl Evaluable for Opcode {
    /// Run a single step of the interpreter.
    ///
    /// This is useful for testing & debugging, as we can set up the exact state we want in order to
    /// trigger some behavior.
    fn eval(
        &self,
        flags: VerificationFlags,
        script: &[u8],
        checker: &dyn SignatureChecker,
        state: &mut State,
    ) -> Result<(), ScriptError> {
        match self {
            Opcode::PushValue(pv) => {
                if pv.value().map_or(0, |v| v.len()) <= push_value::MAX_SIZE {
                    if should_exec(&state.vexec) {
                        pv.eval(flags, script, checker, state)
                    } else {
                        Ok(())
                    }
                } else {
                    Err(ScriptError::PushSize(None))
                }
            }
            Opcode::Operation(op) => op.eval(flags, script, checker, state),
        }
    }
}

impl Serializable for Opcode {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Opcode::PushValue(v) => v.to_bytes(),
            Opcode::Operation(v) => v.to_bytes(),
        }
    }

    fn from_bytes(script: &[u8]) -> Result<(Self, &[u8]), ScriptError> {
        PushValue::from_bytes(script)
            .map(|(pv, rem)| (Opcode::PushValue(pv), rem))
            .or_else(|err| match err {
                ScriptError::SigPushOnly => {
                    Operation::from_bytes(script).map(|(op, rem)| (Opcode::Operation(op), rem))
                }
                _ => Err(err),
            })
    }
}
