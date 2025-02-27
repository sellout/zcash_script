use crate::{
    opcode::{
        self,
        Control::*,
        LargeValue::*,
        Normal::*,
        Opcode::{self, Operation, PushValue},
        Operation::{Control, Normal},
        PushValue::{LargeValue, SmallValue},
        SmallValue::*,
        OP_CHECKLOCKTIMEVERIFY,
    },
    script::{self, Parsable},
    scriptnum::*,
};

// Much of this comes from
// https://gist.github.com/str4d/9d80f1b60e6787310897044502cb025b

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentifiedScriptPubKey {
    P2PKH([u8; 20]),
    P2SH([u8; 20]),
}

impl IdentifiedScriptPubKey {
    pub fn identify(script: &[Opcode]) -> Option<Self> {
        match script {
            [Operation(Normal(OP_DUP)), Operation(Normal(OP_HASH160)), PushValue(LargeValue(PushdataBytelength(hash))), Operation(Normal(OP_EQUALVERIFY)), Operation(Normal(OP_CHECKSIG))] =>
            {
                hash[..]
                    // FIXME: This should use `as_array`, but currently only in nightly.
                    .first_chunk::<0x14>()
                    .cloned()
                    .map(Self::P2PKH)
            }
            [Operation(Normal(OP_HASH160)), PushValue(LargeValue(PushdataBytelength(hash))), Operation(Normal(OP_EQUAL))] =>
            {
                hash[..]
                    // FIXME: This should use `as_array`, but currently only in nightly.
                    .first_chunk::<0x14>()
                    .cloned()
                    .map(Self::P2SH)
            }
            _ => None,
        }
    }

    pub fn serialize(&self) -> Vec<Opcode> {
        match self {
            Self::P2PKH(key_id) => vec![
                Operation(Normal(OP_DUP)),
                Operation(Normal(OP_HASH160)),
                PushValue(push_vec(&key_id[..])),
                Operation(Normal(OP_EQUALVERIFY)),
                Operation(Normal(OP_CHECKSIG)),
            ],
            Self::P2SH(script_id) => vec![
                Operation(Normal(OP_HASH160)),
                PushValue(push_vec(&script_id[..])),
                Operation(Normal(OP_EQUAL)),
            ],
        }
    }
}

enum Pattern {
    EmptyStackCheck,
    MultiSig(u8, u8, bool), // `true` means verify
}

// Named Patterns (not that we can do much with these yet) – should enable via macros

pub const EMPTY_STACK_CHECK: [Opcode; 3] = [
    Operation(Normal(OP_DEPTH)),
    PushValue(SmallValue(OP_0)),
    Operation(Normal(OP_EQUAL)),
];

pub fn ignored_value(v: &[u8]) -> [Opcode; 2] {
    [PushValue(push_vec(v)), Operation(Normal(OP_DROP))]
}

// pub const combined_multisig: Vec<Opcode> = t_of_n_multisigverify + t_of_n_multisig;

// abstractions

pub fn branch(thn: &[Opcode], els: &[Opcode]) -> Vec<Opcode> {
    [
        &[Operation(Control(OP_IF))],
        thn,
        &[Operation(Control(OP_ELSE))],
        els,
        &[Operation(Control(OP_ENDIF))],
    ]
    .concat()
}

///
/// Example: if_else(size_check(20), [], [OP_RETURN])
pub fn if_else(cond: &[Opcode], thn: &[Opcode], els: &[Opcode]) -> Vec<Opcode> {
    let mut vec = cond.to_vec();
    vec.extend(branch(thn, els));
    vec
}

pub fn check_multisig(sig_count: u8, pks: &[&[u8]], verify: bool) -> Vec<Opcode> {
    [
        &[PushValue(push_num(sig_count.into()))],
        &pks.iter()
            .map(|pk| PushValue(push_vec(pk)))
            .collect::<Vec<Opcode>>()[..],
        &[
            PushValue(push_num(
                pks.len()
                    .try_into()
                    .expect("Should not be more than 20 pubkeys"),
            )),
            Operation(Normal(if verify {
                OP_CHECKMULTISIGVERIFY
            } else {
                OP_CHECKMULTISIG
            })),
        ],
    ]
    .concat()
}

pub fn equals(expected: opcode::PushValue, verify: bool) -> [Opcode; 2] {
    [
        PushValue(expected),
        Operation(Normal(if verify { OP_EQUALVERIFY } else { OP_EQUAL })),
    ]
}

pub fn size_check(expected: u32, verify: bool) -> Vec<Opcode> {
    [
        &[Operation(Normal(OP_SIZE))],
        &equals(push_num(expected.into()), verify)[..],
    ]
    .concat()
}

pub fn check_lock_time_verify(lt: &[u8]) -> [Opcode; 2] {
    [
        PushValue(push_vec(lt)),
        Operation(Normal(OP_CHECKLOCKTIMEVERIFY)),
    ]
}

pub fn htlc(pos_check: &[Opcode], lt: &[u8], hash: &[u8; 20]) -> Vec<Opcode> {
    let mut cltv = check_lock_time_verify(lt).to_vec();
    cltv.push(Operation(Normal(OP_DROP)));
    [
        &branch(pos_check, &cltv),
        &[Operation(Normal(OP_DUP)), Operation(Normal(OP_HASH160))][..],
        &equals(push_vec(hash), true),
        &[Operation(Normal(OP_CHECKSIG))],
    ]
    .concat()
}

/// Produce a minimal `PushValue` that encodes the provided number.
pub fn push_num(n: i64) -> opcode::PushValue {
    push_vec(&ScriptNum(n).getvch())
}

/// Produce a minimal `PushValue` that encodes the provided script. This is particularly useful with
/// P2SH.
pub fn push_script(script: &script::PubKey) -> opcode::PushValue {
    push_vec(&script.to_bytes())
}

/// Produce a minimal `PushValue` for the given data.
///
/// TODO: This panics if the provided `Vec`’s `len` is larger than `u32`. It feels like this should
///       then return in `Option`, but that mucks with the ergonomics.
pub fn push_vec(v: &[u8]) -> opcode::PushValue {
    match v {
        [] => SmallValue(OP_0),
        [byte] => match byte {
            0x81 => SmallValue(OP_1NEGATE),
            1 => SmallValue(OP_1),
            2 => SmallValue(OP_2),
            3 => SmallValue(OP_3),
            4 => SmallValue(OP_4),
            5 => SmallValue(OP_5),
            6 => SmallValue(OP_6),
            7 => SmallValue(OP_7),
            8 => SmallValue(OP_8),
            9 => SmallValue(OP_9),
            10 => SmallValue(OP_10),
            11 => SmallValue(OP_11),
            12 => SmallValue(OP_12),
            13 => SmallValue(OP_13),
            14 => SmallValue(OP_14),
            15 => SmallValue(OP_15),
            16 => SmallValue(OP_16),
            _ => LargeValue(PushdataBytelength(v.to_vec())),
        },
        _ => {
            let len = u32::try_from(v.len()).expect("Vec is too large to be Script data.");
            let vec = v.to_vec();
            LargeValue(if len < 0x4f {
                PushdataBytelength(vec)
            } else if len <= u8::MAX.into() {
                OP_PUSHDATA1(vec)
            } else if len <= u16::MAX.into() {
                OP_PUSHDATA2(vec)
            } else {
                OP_PUSHDATA4(vec)
            })
        }
    }
}

pub fn pay_to_pubkey(pubkey: &[u8]) -> [Opcode; 2] {
    [PushValue(push_vec(pubkey)), Operation(Normal(OP_CHECKSIG))]
}

pub fn pay_to_pubkey_hash(hash: &[u8; 20]) -> Vec<Opcode> {
    [
        &[Operation(Normal(OP_DUP)), Operation(Normal(OP_HASH160))],
        &equals(push_vec(hash), true)[..],
        &[Operation(Normal(OP_CHECKSIG))],
    ]
    .concat()
}

pub fn pay_to_script_hash(hash: &[u8; 20]) -> Vec<Opcode> {
    [
        &[Operation(Normal(OP_HASH160))],
        &equals(push_vec(hash), false)[..],
    ]
    .concat()
}

pub fn sha256_htlc(sha: &[u8; 32], lt: &[u8], hash: &[u8; 20]) -> Vec<Opcode> {
    htlc(&sha256_hashlock(sha, true), lt, hash)
}

pub fn sha256_hashlock(sha: &[u8; 32], verify: bool) -> Vec<Opcode> {
    [
        &[Operation(Normal(OP_SHA256))],
        &equals(push_vec(sha), verify)[..],
    ]
    .concat()
}

pub fn hash160_htlc(hash1: &[u8; 20], lt: &[u8], hash2: &[u8; 20]) -> Vec<Opcode> {
    htlc(
        &[
            &[Operation(Normal(OP_HASH160))],
            &equals(push_vec(hash1), true)[..],
        ]
        .concat()[..],
        lt,
        hash2,
    )
}
