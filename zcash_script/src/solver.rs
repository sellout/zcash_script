//! Solvers for detecting known script kinds.

use alloc::vec::Vec;

use bounded_vec::BoundedVec;

use crate::{
    external::pubkey::PubKey,
    op,
    opcode::{push_value::LargeValue::PushdataBytelength, Evaluable, PushValue},
    script, Opcode,
};

/// Parses a [`script::PubKey`] or [`script::Redeem`] and detects standard scripts.
///
/// If successful, returns the script kind, and any relevant properties parsed from the
/// script. For example, for a P2SH script, the result will contain the script hash; for
/// P2PKH it will contain the key hash, etc.
///
/// Returns `None` if the script is non-standard.
pub fn standard(script_code: &script::Component<Opcode>) -> Option<ScriptKind> {
    match &script_code.0[..] {
        // Pay-to-Script-Hash (P2SH)
        [op::HASH160, Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))), op::EQUAL] => {
            v.as_slice()
                .try_into()
                .ok()
                .map(|hash| ScriptKind::ScriptHash { hash })
        }

        // Pay-to-Public-Key-Hash (P2PKH)
        [op::DUP, op::HASH160, Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))), op::EQUALVERIFY, op::CHECKSIG] => {
            v.as_slice()
                .try_into()
                .ok()
                .map(|hash| ScriptKind::PubKeyHash { hash })
        }

        // Provably prunable, data-carrying output.
        //
        // So long as the script passes the `is_unspendable()` test, and all but the first
        // byte passes the `is_push_only()` test, we don't care what exactly is in the
        // script.
        [op::RETURN, rest @ ..] => rest
            .iter()
            .map(|op| op.extract_push_value().ok().cloned())
            // This `.collect()` is equivalent to `script::Opcode::is_push_only` for the
            // subset of inputs consisting of entirely valid `PushValue`s, which is all we
            // care about here.
            .collect::<Option<_>>()
            .map(|data| ScriptKind::NullData { data }),

        // Legacy Pay-to-Public-Key (P2PK), which only occurred in early Zcash coinbase outputs.
        [Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))), op::CHECKSIG] => {
            valid_size_pubkey(v.as_slice()).map(|data| ScriptKind::PubKey { data })
        }

        // Pay-to-Multi-Signature (P2MS)
        [Opcode::PushValue(PushValue::SmallValue(required)), pubkeys @ .., Opcode::PushValue(PushValue::SmallValue(keys)), op::CHECKMULTISIG] =>
        {
            match (u8::try_from(required.to_num()), u8::try_from(keys.to_num())) {
                (Ok(required @ 1..=16), Ok(keys @ 1..=16)) => {
                    // The remaining opcodes must be `PushData`s that are valid lengths for pubkeys.
                    let pubkeys = pubkeys
                        .iter()
                        .map(|op| match op {
                            Opcode::PushValue(data) => valid_size_pubkey(&data.value()),
                            _ => None,
                        })
                        .collect::<Option<Vec<_>>>();

                    pubkeys.and_then(|pubkeys| {
                        (pubkeys.len() == usize::from(keys) && required <= keys)
                            .then_some(ScriptKind::MultiSig { required, pubkeys })
                    })
                }

                // Non-standard
                _ => None,
            }
        }

        // Non-standard
        _ => None,
    }
}

/// Returns the bytes as a public key if their length is the one their first byte calls for.
///
/// Equivalent to zcashd's `CPubKey::ValidSize`, which `Solver` applies to the keys of both P2PK
/// and multisig scripts.
fn valid_size_pubkey(
    bytes: &[u8],
) -> Option<BoundedVec<u8, { PubKey::COMPRESSED_SIZE }, { PubKey::SIZE }>> {
    // Equivalent to `CPubKey::GetLen`
    let expected_len = match bytes.first() {
        Some(2 | 3) => Some(PubKey::COMPRESSED_SIZE),
        Some(4 | 6 | 7) => Some(PubKey::SIZE),
        _ => None,
    };
    (expected_len == Some(bytes.len())).then(|| bytes.to_vec().try_into().expect("bounds checked"))
}

/// Known kinds of standard scripts.
pub enum ScriptKind {
    /// A P2PKH script.
    PubKeyHash {
        /// The Hash160 of the public key.
        hash: [u8; 20],
    },

    /// A P2SH script, used in transaction outputs to efficiently commit to other scripts.
    ScriptHash {
        /// The Hash160 of the script.
        hash: [u8; 20],
    },

    /// A transparent threshold multisig script.
    MultiSig {
        /// The number of signatures required to spend.
        required: u8,
        /// The pubkeys that can be used to sign spends.
        pubkeys: Vec<BoundedVec<u8, { PubKey::COMPRESSED_SIZE }, { PubKey::SIZE }>>,
    },

    /// An unspendable `OP_RETURN` script that carries data.
    NullData {
        /// The carried data.
        data: Vec<PushValue>,
    },

    /// A legacy P2PK script.
    PubKey {
        /// The encoded public key.
        data: BoundedVec<u8, { PubKey::COMPRESSED_SIZE }, { PubKey::SIZE }>,
    },
}

impl ScriptKind {
    /// Returns a string identifier for this script kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptKind::PubKeyHash { .. } => "pubkeyhash",
            ScriptKind::ScriptHash { .. } => "scripthash",
            ScriptKind::MultiSig { .. } => "multisig",
            ScriptKind::NullData { .. } => "nulldata",
            ScriptKind::PubKey { .. } => "pubkey",
        }
    }

    /// Returns the number of signatures required to spend an output of this script kind.
    pub fn req_sigs(&self) -> u8 {
        match self {
            ScriptKind::PubKeyHash { .. } => 1,
            ScriptKind::ScriptHash { .. } => 1,
            ScriptKind::MultiSig { required, .. } => *required,
            // TODO: null-data value might be incorrect,
            //       fix after https://github.com/zcash/wallet/issues/236
            ScriptKind::NullData { .. } => 0,
            ScriptKind::PubKey { .. } => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::standard;
    use crate::script;

    fn kind(bytes: Vec<u8>) -> Option<&'static str> {
        standard(&script::PubKey::parse(&script::Code(bytes)).expect("parses"))
            .map(|kind| kind.as_str())
    }

    /// `<key> OP_CHECKSIG`, with a key of `len` bytes that starts with `prefix`.
    fn p2pk(prefix: u8, len: usize) -> Vec<u8> {
        let len_byte = u8::try_from(len).expect("a direct push");
        [&[len_byte, prefix][..], &vec![0x11; len - 1], &[0xac]].concat()
    }

    /// Like zcashd's `MatchPayToPubkey`, which requires `CPubKey::ValidSize`.
    #[test]
    fn p2pk_requires_a_key_prefix_matching_its_length() {
        for (prefix, len) in [(0x02, 33), (0x03, 33), (0x04, 65), (0x06, 65), (0x07, 65)] {
            assert_eq!(
                kind(p2pk(prefix, len)),
                Some("pubkey"),
                "{prefix:#04x}, {len}"
            );
        }
        for (prefix, len) in [
            (0x00, 33),
            (0x04, 33),
            (0x05, 33),
            (0x02, 65),
            (0x03, 65),
            (0x00, 65),
        ] {
            assert_eq!(kind(p2pk(prefix, len)), None, "{prefix:#04x}, {len}");
        }
    }
}
