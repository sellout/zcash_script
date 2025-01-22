#![allow(non_camel_case_types)]

use std::ops::{Add, Neg, Sub};

use enum_primitive::FromPrimitive;

use super::script_error::*;

pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520; // bytes

/// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: usize = 10_000;

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: ScriptNum = ScriptNum(500_000_000); // Tue Nov  5 00:53:20 1985 UTC

/** Script opcodes */
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Opcode {
    PushValue(PushValue),
    Operation(Operation),
}

impl From<&Opcode> for Vec<u8> {
    fn from(value: &Opcode) -> Self {
        match value {
            Opcode::PushValue(v) => v.into(),
            Opcode::Operation(v) => vec![(*v).into()],
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
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
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PushValue {
    SmallValue(SmallValue),
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
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Operation {
    Control(Control),
    Disabled(Disabled),
    Normal(Normal),
}

impl From<Operation> for u8 {
    fn from(value: Operation) -> Self {
        match value {
            Operation::Control(v) => v.into(),
            Operation::Disabled(v) => v.into(),
            Operation::Normal(v) => v.into(),
        }
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

enum_from_primitive! {
/// Control operations are evaluated regardless of whether the current branch is active.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Control {
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
}
}

impl From<Control> for u8 {
    fn from(value: Control) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

enum_from_primitive! {
/// Disabled operations fail whenever they appear in a script, regardless of whether they are on an
/// active branch.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Disabled {
    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
        // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    // numeric
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    //crypto
    OP_CODESEPARATOR = 0xab,
}
}

impl From<Disabled> for u8 {
    fn from(value: Disabled) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

enum_from_primitive! {
/// Normal operations are only executed when they are on an active branch.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Normal {
    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_SIZE = 0x82,

    // bit logic
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_NOP2 = 0xb1,
    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
}
}

use Normal::*;

pub const OP_CHECKLOCKTIMEVERIFY: Normal = OP_NOP2;

impl From<Normal> for u8 {
    fn from(value: Normal) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

impl TryFrom<u8> for Operation {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Control::from_u8(value).map_or(
            Disabled::from_u8(value).map_or(
                Normal::from_u8(value).map_or(Err(()), |op| Ok(Operation::Normal(op))),
                |op| Ok(Operation::Disabled(op)),
            ),
            |op| Ok(Operation::Control(op)),
        )
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ScriptNum(pub i64);

impl ScriptNum {
    const DEFAULT_MAX_NUM_SIZE: usize = 4;

    pub fn new(
        vch: &Vec<u8>,
        require_minimal: bool,
        max_num_size: Option<usize>,
    ) -> Result<Self, ScriptNumError> {
        let max_num_size = max_num_size.unwrap_or(Self::DEFAULT_MAX_NUM_SIZE);
        if vch.len() > max_num_size {
            return Err(ScriptNumError::Overflow {
                max_num_size,
                actual: vch.len(),
            });
        }
        if require_minimal && !vch.is_empty() {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
            if (vch.last().unwrap_or_else(|| unreachable!()) & 0x7F) == 0 {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit. An example of this case
                // is +-255, which encode to 0xff00 and 0xff80 respectively.
                // (big-endian).
                if vch.len() <= 1 {
                    return Err(ScriptNumError::NegativeZero);
                } else if (vch[vch.len() - 2] & 0x80) == 0 {
                    return Err(ScriptNumError::NonMinimalEncoding);
                }
            }
        }
        Self::set_vch(vch).map(ScriptNum)
    }

    pub fn getint(&self) -> i32 {
        if self.0 > i32::MAX.into() {
            i32::MAX
        } else if self.0 < i32::MIN.into() {
            i32::MIN
        } else {
            self.0.try_into().unwrap()
        }
    }

    pub fn getvch(&self) -> Vec<u8> {
        Self::serialize(&self.0)
    }

    pub fn serialize(value: &i64) -> Vec<u8> {
        if *value == 0 {
            return Vec::new();
        }

        if *value == i64::MIN {
            // The code below is buggy, and produces the "wrong" result for
            // INT64_MIN. To avoid undefined behavior while attempting to
            // negate a value of INT64_MIN, we intentionally return the result
            // that the code below would produce on an x86_64 system.
            return vec![0, 0, 0, 0, 0, 0, 0, 128, 128];
        }

        let mut result = Vec::new();
        let neg = *value < 0;
        let mut absvalue = value.abs();

        while absvalue != 0 {
            result.push(
                (absvalue & 0xff)
                    .try_into()
                    .unwrap_or_else(|_| unreachable!()),
            );
            absvalue >>= 8;
        }

        //    - If the most significant byte is >= 0x80 and the value is positive, push a
        //    new zero-byte to make the significant byte < 0x80 again.

        //    - If the most significant byte is >= 0x80 and the value is negative, push a
        //    new 0x80 byte that will be popped off when converting to an integral.

        //    - If the most significant byte is < 0x80 and the value is negative, add
        //    0x80 to it, since it will be subtracted and interpreted as a negative when
        //    converting to an integral.

        if result.last().map_or(true, |last| last & 0x80 != 0) {
            result.push(if neg { 0x80 } else { 0 });
        } else if neg {
            if let Some(last) = result.last_mut() {
                *last |= 0x80;
            }
        }

        result
    }

    fn set_vch(vch: &Vec<u8>) -> Result<i64, ScriptNumError> {
        match vch.last() {
            None => Ok(0),
            Some(vch_back) => {
                if *vch == vec![0, 0, 0, 0, 0, 0, 0, 128, 128] {
                    // On an x86_64 system, the code below would actually decode the buggy
                    // INT64_MIN encoding correctly. However in this case, it would be
                    // performing left shifts of a signed type by 64, which has undefined
                    // behavior.
                    return Ok(i64::MIN);
                };

                // Guard against undefined behavior. INT64_MIN is the only allowed 9-byte encoding.
                if vch.len() > 8 {
                    return Err(ScriptNumError::Overflow {
                        max_num_size: 8,
                        actual: vch.len(),
                    });
                };

                let mut result: i64 = 0;
                for (i, vch_i) in vch.iter().enumerate() {
                    result |= i64::from(*vch_i) << (8 * i);
                }

                // If the input vector's most significant byte is 0x80, remove it from
                // the result's msb and return a negative.
                if vch_back & 0x80 != 0 {
                    return Ok(-(result & !(0x80 << (8 * (vch.len() - 1)))));
                };

                Ok(result)
            }
        }
    }
}

impl Add for ScriptNum {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let rhs = other.0;
        assert!(
            rhs == 0
                || (rhs > 0 && self.0 <= i64::MAX - rhs)
                || (rhs < 0 && self.0 >= i64::MIN - rhs)
        );
        Self(self.0 + rhs)
    }
}

impl Sub for ScriptNum {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let rhs = other.0;
        assert!(
            rhs == 0
                || (rhs > 0 && self.0 >= i64::MIN + rhs)
                || (rhs < 0 && self.0 <= i64::MAX + rhs)
        );
        Self(self.0 - rhs)
    }
}

impl Neg for ScriptNum {
    type Output = Self;

    fn neg(self) -> Self {
        assert!(self.0 != i64::MIN);
        Self(-self.0)
    }
}

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
