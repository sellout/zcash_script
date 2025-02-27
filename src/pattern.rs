use crate::{
    op,
    opcode::{
        self,
        LargeValue::*,
        Opcode::{self, PushValue},
        PushValue::LargeValue,
    },
    pv,
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
            [op::DUP, op::HASH160, PushValue(LargeValue(PushdataBytelength(hash))), op::EQUALVERIFY, op::CHECKSIG] =>
            {
                hash[..]
                    // FIXME: This should use `as_array`, but currently only in nightly.
                    .first_chunk::<0x14>()
                    .cloned()
                    .map(Self::P2PKH)
            }
            [op::HASH160, PushValue(LargeValue(PushdataBytelength(hash))), op::EQUAL] => {
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
                op::DUP,
                op::HASH160,
                PushValue(push_vec(&key_id[..])),
                op::EQUALVERIFY,
                op::CHECKSIG,
            ],
            Self::P2SH(script_id) => {
                vec![op::HASH160, PushValue(push_vec(&script_id[..])), op::EQUAL]
            }
        }
    }
}

enum Pattern {
    EmptyStackCheck,
    MultiSig(u8, u8, bool), // `true` means verify
}

// Named Patterns (not that we can do much with these yet) – should enable via macros

pub const EMPTY_STACK_CHECK: [Opcode; 3] = [op::DEPTH, op::_0, op::EQUAL];

pub fn ignored_value(v: &[u8]) -> [Opcode; 2] {
    [PushValue(push_vec(v)), op::DROP]
}

// pub const combined_multisig: Vec<Opcode> = t_of_n_multisigverify + t_of_n_multisig;

// abstractions

pub fn branch(thn: &[Opcode], els: &[Opcode]) -> Vec<Opcode> {
    [&[op::IF], thn, &[op::ELSE], els, &[op::ENDIF]].concat()
}

///
/// Example: if_else(size_check(20), [], [op::RETURN])
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
            if verify {
                op::CHECKMULTISIGVERIFY
            } else {
                op::CHECKMULTISIG
            },
        ],
    ]
    .concat()
}

pub fn equals(expected: opcode::PushValue, verify: bool) -> [Opcode; 2] {
    [
        PushValue(expected),
        if verify { op::EQUALVERIFY } else { op::EQUAL },
    ]
}

pub fn size_check(expected: u32, verify: bool) -> Vec<Opcode> {
    [&[op::SIZE], &equals(push_num(expected.into()), verify)[..]].concat()
}

pub fn check_lock_time_verify(lt: &[u8]) -> [Opcode; 2] {
    [PushValue(push_vec(lt)), op::CHECKLOCKTIMEVERIFY]
}

pub fn htlc(pos_check: &[Opcode], lt: &[u8], hash: &[u8; 20]) -> Vec<Opcode> {
    let mut cltv = check_lock_time_verify(lt).to_vec();
    cltv.push(op::DROP);
    [
        &branch(pos_check, &cltv),
        &[op::DUP, op::HASH160][..],
        &equals(push_vec(hash), true),
        &[op::CHECKSIG],
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
        [] => pv::_0,
        [byte] => match byte {
            0x81 => pv::_1NEGATE,
            1 => pv::_1,
            2 => pv::_2,
            3 => pv::_3,
            4 => pv::_4,
            5 => pv::_5,
            6 => pv::_6,
            7 => pv::_7,
            8 => pv::_8,
            9 => pv::_9,
            10 => pv::_10,
            11 => pv::_11,
            12 => pv::_12,
            13 => pv::_13,
            14 => pv::_14,
            15 => pv::_15,
            16 => pv::_16,
            _ => pv::pushdata_bytelength(v.to_vec()),
        },
        _ => {
            let len = u32::try_from(v.len()).expect("Vec is too large to be Script data.");
            let vec = v.to_vec();
            if len < 0x4f {
                pv::pushdata_bytelength(vec)
            } else if len <= u8::MAX.into() {
                pv::pushdata1(vec)
            } else if len <= u16::MAX.into() {
                pv::pushdata2(vec)
            } else {
                pv::pushdata4(vec)
            }
        }
    }
}

pub fn pay_to_pubkey(pubkey: &[u8]) -> [Opcode; 2] {
    [PushValue(push_vec(pubkey)), op::CHECKSIG]
}

pub fn pay_to_pubkey_hash(hash: &[u8; 20]) -> Vec<Opcode> {
    [
        &[op::DUP, op::HASH160],
        &equals(push_vec(hash), true)[..],
        &[op::CHECKSIG],
    ]
    .concat()
}

pub fn pay_to_script_hash(hash: &[u8; 20]) -> Vec<Opcode> {
    [&[op::HASH160], &equals(push_vec(hash), false)[..]].concat()
}

pub fn sha256_htlc(sha: &[u8; 32], lt: &[u8], hash: &[u8; 20]) -> Vec<Opcode> {
    htlc(&sha256_hashlock(sha, true), lt, hash)
}

pub fn sha256_hashlock(sha: &[u8; 32], verify: bool) -> Vec<Opcode> {
    [&[op::SHA256], &equals(push_vec(sha), verify)[..]].concat()
}

pub fn hash160_htlc(hash1: &[u8; 20], lt: &[u8], hash2: &[u8; 20]) -> Vec<Opcode> {
    htlc(
        &[&[op::HASH160], &equals(push_vec(hash1), true)[..]].concat()[..],
        lt,
        hash2,
    )
}
