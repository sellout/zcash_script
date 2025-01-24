use enum_primitive::FromPrimitive;

use super::opcode::{LargeValue::*, Normal::*, SmallValue::*, *};
use super::script_error::*;
use super::scriptnum::*;

pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520; // bytes

/// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: usize = 10_000;

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: ScriptNum = ScriptNum(500_000_000); // Tue Nov  5 00:53:20 1985 UTC

/** Serialized script, used inside transaction inputs and outputs */
#[derive(Clone, Debug)]
pub struct Script<'a>(pub &'a [u8]);

impl Script<'_> {
    pub fn parse(&self) -> Result<Vec<Option<Opcode>>, ScriptError> {
        let mut pc = self.0;
        let mut result = vec![];
        while !pc.is_empty() {
            Self::get_op(&mut pc).map(|op| result.push(op))?;
        }
        Ok(result)
    }

    pub fn get_op(script: &mut &[u8]) -> Result<Option<Opcode>, ScriptError> {
        if script.is_empty() {
            panic!("attempting to parse an opcode from an empty script");
        }

        let guard_oob = |script: &[u8], needed_bytes: usize| {
            if needed_bytes <= script.len() {
                Ok(())
            } else {
                Err(ScriptError::ReadError {
                    expected_bytes: needed_bytes,
                    available_bytes: script.len(),
                })
            }
        };

        let read_le = |script: &mut &[u8], needed_bytes: usize| {
            guard_oob(script, needed_bytes).map(|()| {
                let mut size = 0;
                for i in (0..needed_bytes).rev() {
                    size <<= 8;
                    size |= usize::from(script[i]);
                }
                *script = &script[needed_bytes..];
                size
            })
        };

        let read_push_value = |script: &mut &[u8], size: usize| {
            guard_oob(script, size).map(|()| {
                let value = &script[0..size];
                *script = &script[size..];
                value.to_vec()
            })
        };

        let read_push_data = |script: &mut &[u8], needed_bytes: usize| {
            read_le(script, needed_bytes).and_then(|size| read_push_value(script, size))
        };

        let make_lv = |pv: LargeValue| Some(Opcode::PushValue(PushValue::LargeValue(pv)));

        let leading_byte = script[0];
        *script = &script[1..];
        match leading_byte {
            0x4c => read_push_data(script, 1).map(|v| make_lv(OP_PUSHDATA1(v))),
            0x4d => read_push_data(script, 2).map(|v| make_lv(OP_PUSHDATA2(v))),
            0x4e => read_push_data(script, 4).map(|v| make_lv(OP_PUSHDATA4(v))),
            _ => {
                if 0x01 <= leading_byte && leading_byte < 0x4c {
                    read_push_value(script, leading_byte.into())
                        .map(|v| make_lv(PushdataBytelength(v)))
                } else {
                    Ok(SmallValue::from_u8(leading_byte).map_or(
                        Operation::try_from(leading_byte)
                            .map(Opcode::Operation)
                            .ok(),
                        |sv| Some(Opcode::PushValue(PushValue::SmallValue(sv))),
                    ))
                }
            }
        }
    }

    pub fn serialize(script: &[Opcode]) -> Vec<u8> {
        script
            .iter()
            .fold(Vec::new(), |acc, op| [acc, op.into()].concat())
    }

    /** Encode/decode small integers: */
    pub fn decode_op_n(opcode: SmallValue) -> u32 {
        if opcode == OP_0 {
            return 0;
        }
        assert!(opcode >= OP_1 && opcode <= OP_16);
        (u8::from(opcode) - (u8::from(OP_1) - 1)).into()
    }

    /// Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    /// as 20 sigops. With pay-to-script-hash, that changed:
    /// CHECKMULTISIGs serialized in script_sigs are
    /// counted more accurately, assuming they are of the form
    ///  ... OP_N CHECKMULTISIG ...
    pub fn get_sig_op_count(&self, accurate: bool) -> u32 {
        let mut n = 0;
        let mut pc = self.0;
        let mut last_opcode = None;
        while !pc.is_empty() {
            let opcode = match Self::get_op(&mut pc) {
                Ok(o) => o,
                Err(_) => break,
            };
            if let Some(Opcode::Operation(Operation::Normal(op))) = opcode {
                if op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY {
                    n += 1;
                } else if op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY {
                    match last_opcode {
                        Some(Opcode::PushValue(PushValue::SmallValue(pv))) => {
                            if accurate && pv >= OP_1 && pv <= OP_16 {
                                n += Self::decode_op_n(pv);
                            } else {
                                n += 20
                            }
                        }
                        _ => n += 20,
                    }
                }
            }
            last_opcode = opcode;
        }
        n
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        self.parse().map_or(false, |ops| match &ops[..] {
            [ Some(Opcode::Operation(Operation::Normal(OP_HASH160))),
              Some(Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v)))),
              Some(Opcode::Operation(Operation::Normal(OP_EQUAL)))
            ] => v.len() == 0x14,
            _ => false
        })
    }

    /// Called by `IsStandardTx` and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    pub fn is_push_only(&self) -> bool {
        let mut pc = self.0;
        while !pc.is_empty() {
            if let Ok(Some(Opcode::PushValue(_))) = Self::get_op(&mut pc) {
            } else {
                return false;
            }
        }
        true
    }
}
