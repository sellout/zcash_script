#![allow(non_camel_case_types)]

use enum_primitive::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::interpreter::*;
use crate::script_error::*;
use crate::scriptnum::*;

pub const MAX_SIZE: usize = 520; // bytes

fn read_le<const N: usize>(script: &[u8]) -> Result<(usize, &[u8]), ScriptError> {
    match script.split_first_chunk::<N>() {
        None => Err(ScriptError::ReadError {
            expected_bytes: N,
            available_bytes: script.len(),
        }),
        Some((first, rest)) => {
            let mut size = 0;
            for i in first.iter().rev() {
                size <<= 8;
                size |= usize::from(*i);
            }
            Ok((size, rest))
        }
    }
}

fn read_push_value(script: &[u8], needed_bytes: usize) -> Result<(&[u8], &[u8]), ScriptError> {
    match script.split_at_checked(needed_bytes) {
        None => Err(ScriptError::ReadError {
            expected_bytes: needed_bytes,
            available_bytes: script.len(),
        }),
        Some((first, rest)) => Ok((first, rest)),
    }
}

fn read_push_data<const N: usize>(script: &[u8]) -> Result<(&[u8], &[u8]), ScriptError> {
    read_le::<N>(script).and_then(|(size, rest)| read_push_value(rest, size))
}

impl Serializable for PushValue {
    fn to_bytes(&self) -> Vec<u8> {
        self.into()
    }

    fn from_bytes(script: &[u8]) -> Result<(Self, &[u8]), ScriptError> {
        let make_lv = PushValue::LargeValue;

        match script.split_first() {
            None => panic!("attempting to parse an opcode from an empty script"),
            Some((&leading_byte, script)) => match leading_byte {
                0x4c => read_push_data::<1>(script)
                    .map(|(v, rest)| (make_lv(OP_PUSHDATA1(v.to_vec())), rest)),
                0x4d => read_push_data::<2>(script)
                    .map(|(v, rest)| (make_lv(OP_PUSHDATA2(v.to_vec())), rest)),
                0x4e => read_push_data::<4>(script)
                    .map(|(v, rest)| (make_lv(OP_PUSHDATA4(v.to_vec())), rest)),
                _ => {
                    if 0x01 <= leading_byte && leading_byte < 0x4c {
                        read_push_value(script, leading_byte.into())
                            .map(|(v, rest)| (make_lv(PushdataBytelength(v.to_vec())), rest))
                    } else {
                        SmallValue::from_u8(leading_byte)
                            .ok_or(ScriptError::SigPushOnly)
                            .map(|sv| (PushValue::SmallValue(sv), script))
                    }
                }
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum LargeValue {
    // push value
    PushdataBytelength(Vec<u8>),
    OP_PUSHDATA1(Vec<u8>),
    OP_PUSHDATA2(Vec<u8>),
    OP_PUSHDATA4(Vec<u8>),
}

use LargeValue::*;

impl From<&LargeValue> for Vec<u8> {
    fn from(value: &LargeValue) -> Self {
        let bytes = value.value();
        match value {
            PushdataBytelength(_) => {
                [ScriptNum(bytes.len().try_into().unwrap()).getvch(), bytes].concat()
            }
            OP_PUSHDATA1(_) => [
                vec![0x4c],
                ScriptNum(bytes.len().try_into().unwrap()).getvch(),
                bytes,
            ]
            .concat(),
            OP_PUSHDATA2(_) => [
                vec![0x4d],
                ScriptNum(bytes.len().try_into().unwrap()).getvch(),
                bytes,
            ]
            .concat(),
            OP_PUSHDATA4(_) => [
                vec![0x4e],
                ScriptNum(bytes.len().try_into().unwrap()).getvch(),
                bytes,
            ]
            .concat(),
        }
    }
}
impl LargeValue {
    pub fn value(&self) -> Vec<u8> {
        match self {
            PushdataBytelength(v) | OP_PUSHDATA1(v) | OP_PUSHDATA2(v) | OP_PUSHDATA4(v) => {
                v.clone()
            }
        }
    }

    pub fn is_minimal_push(&self) -> bool {
        match self {
            PushdataBytelength(data) => match data.len() {
                1 => data[0] != 0x81 && (data[0] < 1 || 16 < data[0]),
                _ => true,
            },
            OP_PUSHDATA1(data) => 0x4c <= data.len(),
            OP_PUSHDATA2(data) => 0x100 <= data.len(),
            OP_PUSHDATA4(data) => 0x10000 <= data.len(),
        }
    }
}

enum_from_primitive! {
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum SmallValue {
    // push value
    OP_0 = 0x00,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,
}
}

use SmallValue::*;

impl SmallValue {
    pub fn value(&self) -> Option<Vec<u8>> {
        match self {
            OP_0 => Some(vec![]),
            OP_1NEGATE => Some(vec![0x81]),
            OP_RESERVED => None,
            _ => Some(vec![u8::from(self.clone()) - (u8::from(OP_1) - 1)]),
        }
    }
}

impl From<SmallValue> for u8 {
    fn from(value: SmallValue) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum PushValue {
    /// - can be cast to its discriminant
    SmallValue(SmallValue),
    /// - variable-length representation
    LargeValue(LargeValue),
}

impl PushValue {
    pub fn value(&self) -> Option<Vec<u8>> {
        match self {
            PushValue::LargeValue(pv) => Some(pv.value()),
            PushValue::SmallValue(pv) => pv.value(),
        }
    }

    pub fn is_minimal_push(&self) -> bool {
        match self {
            PushValue::LargeValue(lv) => lv.is_minimal_push(),
            PushValue::SmallValue(_) => true,
        }
    }

    pub fn eval_(
        &self,
        require_minimal: bool,
        stack: &mut Stack<Vec<u8>>,
    ) -> Result<(), ScriptError> {
        if require_minimal && !self.is_minimal_push() {
            Err(ScriptError::MinimalData)
        } else {
            self.value()
                .map_or(Err(ScriptError::BadOpcode(None)), |v| Ok(stack.push(v)))
        }
    }
}

impl Evaluable for PushValue {
    fn eval(
        &self,
        flags: VerificationFlags,
        _script: &[u8],
        _checker: &dyn SignatureChecker,
        state: &mut State,
    ) -> Result<(), ScriptError> {
        self.eval_(
            flags.contains(VerificationFlags::MinimalData),
            &mut state.stack,
        )
    }
}

impl From<&PushValue> for Vec<u8> {
    fn from(value: &PushValue) -> Self {
        match value {
            PushValue::SmallValue(v) => vec![(*v).into()],
            PushValue::LargeValue(v) => v.into(),
        }
    }
}
