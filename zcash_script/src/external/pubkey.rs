#[cfg(feature = "signature-validation")]
use secp256k1::{ecdsa, Message, PublicKey};

#[cfg_attr(not(feature = "signature-validation"), allow(dead_code))]
pub(crate) struct PubKey<'a>(pub(crate) &'a [u8]);

impl PubKey<'_> {
    pub(crate) const SIZE: usize = 65;
    pub(crate) const COMPRESSED_SIZE: usize = 33;

    /// Check syntactic correctness: the key is the length its first byte calls for. This is
    /// zcashd’s `CPubKey::IsValid` for a key built from these bytes.
    ///
    /// Note that this is consensus-critical as `check_sig` calls it! It only lets `check_sig` fail
    /// before computing the sighash, though, since `verify` fails on any key it rejects.
    #[cfg(feature = "signature-validation")]
    pub(crate) fn is_valid(&self) -> bool {
        let expected_len = match self.0.first() {
            Some(0x02 | 0x03) => Some(Self::COMPRESSED_SIZE),
            Some(0x04 | 0x06 | 0x07) => Some(Self::SIZE),
            _ => None,
        };
        expected_len == Some(self.0.len())
    }

    /// Verify a signature (~72 bytes).
    /// If this public key is not fully valid, the return value will be false.
    #[cfg(feature = "signature-validation")]
    pub(crate) fn verify(&self, hash: &[u8; 32], sig: &ecdsa::Signature) -> bool {
        if !self.is_valid() {
            return false;
        };

        if let Ok(pubkey) = PublicKey::from_slice(self.0) {
            let mut normalized_sig = *sig;
            // libsecp256k1's ECDSA verification requires lower-S signatures, which are
            // not required by consensus in Zcash, so normalize them first.
            normalized_sig.normalize_s();
            ecdsa::verify(&normalized_sig, Message::from_digest(*hash), &pubkey).is_ok()
        } else {
            false
        }
    }

    #[cfg(feature = "signature-validation")]
    pub(crate) fn check_low_s(sig: &ecdsa::Signature) -> bool {
        let mut check = *sig;
        check.normalize_s();
        sig == &check
    }
}

#[cfg(all(test, feature = "signature-validation"))]
mod tests {
    use alloc::vec::Vec;

    use super::PubKey;

    #[test]
    fn is_valid_requires_the_length_the_prefix_calls_for() {
        let key = |prefix: u8, len: usize| [&[prefix][..], &[0x11; 64][..len - 1]].concat();
        for (prefix, len) in [(0x02, 33), (0x03, 33), (0x04, 65), (0x06, 65), (0x07, 65)] {
            assert!(PubKey(&key(prefix, len)).is_valid(), "{prefix:#04x}, {len}");
        }
        for (prefix, len) in [(0x02, 65), (0x04, 33), (0x05, 33), (0x00, 33), (0x02, 34)] {
            assert!(
                !PubKey(&key(prefix, len)).is_valid(),
                "{prefix:#04x}, {len}"
            );
        }
        assert!(!PubKey(&Vec::new()).is_valid());
    }
}
