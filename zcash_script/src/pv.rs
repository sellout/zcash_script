//! Convenience definitions for all push values.

#![allow(missing_docs)]

use crate::{
    num,
    opcode::{
        self,
        push_value::SmallValue::*,
        PushValue::{self, SmallValue},
    },
    script::{self, Evaluable},
};

pub const _0: PushValue = SmallValue(OP_0);
pub const _1NEGATE: PushValue = SmallValue(OP_1NEGATE);
pub const _1: PushValue = SmallValue(OP_1);
pub const _2: PushValue = SmallValue(OP_2);
pub const _3: PushValue = SmallValue(OP_3);
pub const _4: PushValue = SmallValue(OP_4);
pub const _5: PushValue = SmallValue(OP_5);
pub const _6: PushValue = SmallValue(OP_6);
pub const _7: PushValue = SmallValue(OP_7);
pub const _8: PushValue = SmallValue(OP_8);
pub const _9: PushValue = SmallValue(OP_9);
pub const _10: PushValue = SmallValue(OP_10);
pub const _11: PushValue = SmallValue(OP_11);
pub const _12: PushValue = SmallValue(OP_12);
pub const _13: PushValue = SmallValue(OP_13);
pub const _14: PushValue = SmallValue(OP_14);
pub const _15: PushValue = SmallValue(OP_15);
pub const _16: PushValue = SmallValue(OP_16);

/// Produces a minimally-encoded data value. It fails if the slice is larger than
/// `LargeValue::MAX_SIZE`.
pub fn push_value(value: &[u8]) -> Option<PushValue> {
    PushValue::from_slice(value)
}

/// Produce a minimal `PushValue` that encodes the provided number.
pub fn push_num(n: i64) -> PushValue {
    push_value(&num::serialize(n)).expect("all i64 can be encoded as `PushValue`")
}

/// Produce a minimal `PushValue` that encodes the provided script. This is particularly useful with
/// P2SH.
pub fn push_script<T: Into<opcode::PossiblyBad> + opcode::Evaluable + Clone>(
    script: &script::Component<T>,
) -> Option<PushValue> {
    push_value(&script.to_bytes())
}

/// Creates a `PushValue` from a 20-byte value (basically, RipeMD160 and other hashes).
///
/// __TODO__: Once const_generic_exprs lands, this should become `push_array<N>(a: &[u8; N])` with
///           `N` bounded by [`opcode::push_value::LargeValue::MAX_SIZE`].
pub fn push_160b_hash(hash: &[u8; 20]) -> PushValue {
    push_value(hash).expect("20 is a valid data size")
}

/// Creates a `PushValue` from a 32-byte value (basically, SHA-256 and other hashes).
///
/// __TODO__: Once const_generic_exprs lands, this should become `push_array<N>(a: &[u8; N])` with
///           `N` bounded by [`opcode::push_value::LargeValue::MAX_SIZE`].
pub fn push_256b_hash(hash: &[u8; 32]) -> PushValue {
    push_value(hash).expect("32 is a valid data size")
}
