use std::num::TryFromIntError;

use secp256k1::ecdsa;

use crate::{
    external::pubkey::PubKey,
    interpreter::*,
    script::{self, Parsable, Script},
    scriptnum::*,
    util::and_maybe::AndMaybe,
};

/// This maps to `zcash_script_error_t`, but most of those cases aren’t used any more. This only
/// replicates the still-used cases, and then an `Unknown` bucket for anything else that might
/// happen.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Any failure that results in the script being invalid.
    ///
    /// __NB__: This is in `Option` because this type is used by both the C++ and Rust
    ///         implementations, but the C++ impl doesn’t yet expose the original error.
    Ok(Option<script::Error>),
    /// An exception was caught.
    VerifyScript,
    /// The script size can’t fit in a `u32`, as required by the C++ code.
    InvalidScriptSize(TryFromIntError),
    /// Some other failure value recovered from C++.
    ///
    /// __NB__: Linux uses `u32` for the underlying C++ enum while Windows uses `i32`, so `i64` can
    ///         hold either.
    Unknown(i64),
}

/// The external API of zcash_script. This is defined to make it possible to compare the C++ and
/// Rust implementations.
pub trait ZcashScript {
    /// Returns `Ok(())` if the a transparent input correctly spends the matching output
    ///  under the additional constraints specified by `flags`. This function
    ///  receives only the required information to validate the spend and not
    ///  the transaction itself. In particular, the sighash for the spend
    ///  is obtained using a callback function.
    ///
    ///  - sighash: a callback function which is called to obtain the sighash.
    ///  - n_lock_time: the lock time of the transaction being validated.
    ///  - is_final: a boolean indicating whether the input being validated is final
    ///    (i.e. its sequence number is 0xFFFFFFFF).
    ///  - script_pub_key: the scriptPubKey of the output being spent.
    ///  - script_sig: the scriptSig of the input being validated.
    ///  - flags: the script verification flags to use.
    ///
    ///  Note that script verification failure is indicated by `Err(Error::Ok)`.
    fn verify_callback(
        sighash_callback: SighashCalculator,
        lock_time: i64,
        is_final: bool,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error>;

    /// Returns the number of transparent signature operations in the input or
    /// output script pointed to by script.
    fn legacy_sigop_count_script(script: &[u8]) -> Result<u32, Error>;
}

/// All signature hashes are 32 bytes, since they are either:
/// - a SHA-256 output (for v1 or v2 transactions).
/// - a BLAKE2b-256 output (for v3 and above transactions).
pub const SIGHASH_SIZE: usize = 32;

/// A function which is called to obtain the sighash.
///    - script_code: the scriptCode being validated. Note that this not always
///      matches script_sig, i.e. for P2SH.
///    - hash_type: the hash type being used.
///
/// The `extern "C"` function that calls this doesn’t give much opportunity for rich failure
/// reporting, but returning `None` indicates _some_ failure to produce the desired hash.
pub type SighashCalculator<'a> = &'a dyn Fn(&[u8], HashType) -> Option<[u8; SIGHASH_SIZE]>;

pub struct CallbackTransactionSignatureChecker<'a> {
    pub sighash: SighashCalculator<'a>,
    pub lock_time: &'a ScriptNum,
    pub is_final: bool,
}

impl CallbackTransactionSignatureChecker<'_> {
    pub fn verify_signature(
        sig: &ecdsa::Signature,
        pubkey: &PubKey,
        sighash: &[u8; SIGHASH_SIZE],
    ) -> bool {
        pubkey.verify(sighash, sig)
    }
}

impl SignatureChecker for CallbackTransactionSignatureChecker<'_> {
    fn check_sig(&self, sig: &Signature, vch_pub_key: &[u8], script_code: &[u8]) -> bool {
        let pubkey = PubKey(vch_pub_key);

        pubkey.is_valid()
            && (self.sighash)(script_code, sig.sighash)
                .map(|sighash| Self::verify_signature(&sig.sig, &pubkey, &sighash))
                .unwrap_or(false)
    }

    fn check_lock_time(&self, lock_time: &ScriptNum) -> bool {
        // There are two times of nLockTime: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nLockTime < LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if *self.lock_time < script::LOCKTIME_THRESHOLD && *lock_time >= script::LOCKTIME_THRESHOLD
            || *self.lock_time >= script::LOCKTIME_THRESHOLD && *lock_time < script::LOCKTIME_THRESHOLD
            // Now that we know we're comparing apples-to-apples, the
            // comparison is a simple numeric one.
            || lock_time > self.lock_time
        {
            false
            // Finally the nLockTime feature can be disabled and thus
            // CHECKLOCKTIMEVERIFY bypassed if every txin has been
            // finalized by setting nSequence to maxint. The
            // transaction would be allowed into the blockchain, making
            // the opcode ineffective.
            //
            // Testing if this vin is not final is sufficient to
            // prevent this condition. Alternatively we could test all
            // inputs, but testing just this input minimizes the data
            // required to prove correct CHECKLOCKTIMEVERIFY execution.
        } else {
            !self.is_final
        }
    }
}

/// A tag to indicate that the Rust implementation of zcash_script should be used.
pub enum RustInterpreter {}

impl RustInterpreter {
    fn verify<P>(
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
        payload: &mut P,
        stepper: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), script::Error>,
    ) -> Result<(), Error> {
        script::PubKey::from_bytes(script_pub_key)
            .and_then(|(pub_key, _)| {
                script::sigs_from_bytes(script_sig).and_then(|am| match am {
                    AndMaybe::Only(sig) => {
                        if flags.contains(VerificationFlags::SigPushOnly) {
                            Err(script::Error::SigPushOnly)
                        } else {
                            Script { sig, pub_key }.eval(flags, script_pub_key, payload, stepper)
                        }
                    }
                    AndMaybe::Indeed(_, sig) => {
                        Script { sig, pub_key }.eval(flags, script_pub_key, payload, stepper)
                    }
                })
            })
            .map_err(|e| Error::Ok(Some(e)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepResults {
    identical_states: Vec<State>,
    diverging_result: Option<(Result<State, script::Error>, Result<State, script::Error>)>,
}

impl StepResults {
    pub fn initial() -> Self {
        StepResults {
            identical_states: vec![],
            diverging_result: None,
        }
    }
}

pub fn compare_step<'a>(
    flags: VerificationFlags,
    checker: &'a impl SignatureChecker,
) -> impl Fn(&dyn Evaluable, &[u8], &mut State, &mut StepResults) -> Result<(), script::Error> + 'a
{
    move |pc, script, state, payload| {
        let mut right_state = (*state).clone();
        let left = pc.eval(flags, script, checker, state);
        let right = pc.eval(flags, script, checker, &mut right_state);

        match (left, right) {
            (Ok(()), Ok(())) => {
                if *state == right_state {
                    payload.identical_states.push(state.clone());
                    left
                } else {
                    // In this case, the script hasn’t failed, but we stop running
                    // anything
                    payload.diverging_result = Some((
                        left.map(|_| state.clone()),
                        right.map(|_| right_state.clone()),
                    ));
                    Err(script::Error::UnknownError)
                }
            }
            // at least one is `Err`
            (_, _) => {
                if left != right {
                    payload.diverging_result = Some((
                        left.map(|_| state.clone()),
                        right.map(|_| right_state.clone()),
                    ));
                }
                left.or(right)
            }
        }
    }
}

impl ZcashScript for RustInterpreter {
    /// Returns the number of transparent signature operations in the
    /// transparent inputs and outputs of this transaction.
    fn legacy_sigop_count_script(script: &[u8]) -> Result<u32, Error> {
        script::PubKey::from_bytes(script)
            .map_err(|e| Error::Ok(Some(e)))
            .map(|cscript| cscript.0.get_sig_op_count(false))
    }

    fn verify_callback(
        sighash: SighashCalculator,
        lock_time: i64,
        is_final: bool,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error> {
        let lock_time_num = ScriptNum(lock_time);

        let checker = CallbackTransactionSignatureChecker {
            sighash,
            lock_time: &lock_time_num,
            is_final,
        };
        let stepper = basic_evaluator(flags, &checker);
        Self::verify(script_pub_key, script_sig, flags, &mut (), &stepper)
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use super::*;

    /// Ensures that flags represent a supported state. This avoids crashes in the C++ code, which
    /// break various tests.
    pub fn repair_flags(flags: VerificationFlags) -> VerificationFlags {
        // TODO: The C++ implementation fails an assert (interpreter.cpp:1097) if `CleanStack` is
        //       set without `P2SH`.
        if flags.contains(VerificationFlags::CleanStack) {
            flags & VerificationFlags::P2SH
        } else {
            flags
        }
    }

    /// A `usize` one larger than the longest allowed script, for testing bounds.
    pub const OVERFLOW_SCRIPT_SIZE: usize = script::MAX_SIZE + 1;
}

#[cfg(test)]
mod tests {
    use super::{testing::*, *};
    use crate::pattern::*;
    use hex::FromHex;
    use proptest::prelude::*;

    lazy_static::lazy_static! {
        pub static ref SCRIPT_PUBKEY: Vec<u8> = script::PubKey(pay_to_script_hash(&<[u8; 0x14]>::from_hex("c117756dcbe144a12a7c33a77cfa81aa5aeeb381").expect("valid hash"))).to_bytes();
        pub static ref SCRIPT_SIG: Vec<u8> = script::Sig::new(vec![
            push_num(0),
            push_vec(&<[u8; 0x48]>::from_hex("3045022100d2ab3e6258fe244fa442cfb38f6cef9ac9a18c54e70b2f508e83fa87e20d040502200eead947521de943831d07a350e45af8e36c2166984a8636f0a8811ff03ed09401").expect("valid sig")),
            push_vec(&<[u8; 0x47]>::from_hex("3044022013e15d865010c257eef133064ef69a780b4bc7ebe6eda367504e806614f940c3022062fdbc8c2d049f91db2042d6c9771de6f1ef0b3b1fea76c1ab5542e44ed29ed801").expect("valid sig")),
            push_script(&script::PubKey(check_multisig(
                2,
                &[
                    &<[u8; 0x21]>::from_hex("03b2cc71d23eb30020a4893982a1e2d352da0d20ee657fa02901c432758909ed8f").expect("valid key"),
                    &<[u8; 0x21]>::from_hex("029d1e9a9354c0d2aee9ffd0f0cea6c39bbf98c4066cf143115ba2279d0ba7dabe").expect("valid key"),
                    &<[u8; 0x21]>::from_hex("03e32096b63fd57f3308149d238dcbb24d8d28aad95c0e4e74e3e5e6a11b61bcc4").expect("valid key")
                ],
                false)))
        ]).to_bytes();
    }

    fn sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        <[u8; 32]>::from_hex("e8c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .ok()
    }

    fn invalid_sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        <[u8; 32]>::from_hex("08c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .ok()
    }

    fn missing_sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        None
    }

    #[test]
    fn it_works() {
        let n_lock_time: i64 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let checker = CallbackTransactionSignatureChecker {
            sighash: &sighash,
            lock_time: &ScriptNum(n_lock_time),
            is_final,
        };
        let stepper = compare_step(flags, &checker);
        let mut res = StepResults::initial();
        let ret = RustInterpreter::verify(script_pub_key, script_sig, flags, &mut res, &stepper);

        if res.diverging_result != None {
            panic!("invalid result: {:?}", res);
        }
        assert_eq!(ret, Ok(()));
    }

    #[test]
    fn it_fails_on_invalid_sighash() {
        let n_lock_time: i64 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let checker = CallbackTransactionSignatureChecker {
            sighash: &invalid_sighash,
            lock_time: &ScriptNum(n_lock_time),
            is_final,
        };
        let stepper = compare_step(flags, &checker);
        let mut res = StepResults::initial();
        let ret = RustInterpreter::verify(script_pub_key, script_sig, flags, &mut res, &stepper);

        if res.diverging_result != None {
            panic!("mismatched result: {:?}", res);
        }
        assert_eq!(ret, Err(Error::Ok(Some(script::Error::EvalFalse))));
    }

    #[test]
    fn it_fails_on_missing_sighash() {
        let n_lock_time: i64 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let checker = CallbackTransactionSignatureChecker {
            sighash: &missing_sighash,
            lock_time: &ScriptNum(n_lock_time),
            is_final,
        };
        let stepper = compare_step(flags, &checker);
        let mut res = StepResults::initial();
        let ret = RustInterpreter::verify(script_pub_key, script_sig, flags, &mut res, &stepper);

        if res.diverging_result != None {
            panic!("mismatched result: {:?}", res);
        }
        assert_eq!(ret, Err(Error::Ok(Some(script::Error::EvalFalse))));
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 20_000, .. ProptestConfig::default()
        })]

        /// This test is very shallow, because we have only `()` for success and most errors have
        /// been collapsed to `Error::Ok`. A deeper comparison, requires changes to the C++ code.
        #[test]
        fn test_arbitrary_scripts(
            lock_time in prop::num::i64::ANY,
            is_final in prop::bool::ANY,
            pub_key in prop::collection::vec(0..=0xffu8, 0..=OVERFLOW_SCRIPT_SIZE),
            sig in prop::collection::vec(0..=0xffu8, 1..=OVERFLOW_SCRIPT_SIZE),
            flags in prop::bits::u32::masked(VerificationFlags::all().bits()),
        ) {
            let checker = CallbackTransactionSignatureChecker {
                sighash: &missing_sighash,
                lock_time: &ScriptNum(lock_time),
                is_final,
            };
            let flags = repair_flags(VerificationFlags::from_bits_truncate(flags));
            let stepper = compare_step(flags, &checker);
            let mut res = StepResults::initial();
            let _ = RustInterpreter::verify(&pub_key[..], &sig[..], flags, &mut res, &stepper);

            if res.diverging_result != None {
                panic!("mismatched result: {:?}", res);
            }
        }

        /// Similar to `test_arbitrary_scripts`, but ensures the `sig` only contains pushes.
        #[test]
        fn test_restricted_sig_scripts(
            lock_time in prop::num::i64::ANY,
            is_final in prop::bool::ANY,
            pub_key in prop::collection::vec(0..=0xffu8, 0..=OVERFLOW_SCRIPT_SIZE),
            sig in prop::collection::vec(0..=0x60u8, 0..=OVERFLOW_SCRIPT_SIZE),
            flags in prop::bits::u32::masked(
                // Don’t waste test cases on whether or not `SigPushOnly` is set.
                (VerificationFlags::all() - VerificationFlags::SigPushOnly).bits()),
        ) {
            let checker = CallbackTransactionSignatureChecker {
                sighash: &missing_sighash,
                lock_time: &ScriptNum(lock_time),
                is_final,
            };
            let flags = repair_flags(VerificationFlags::from_bits_truncate(flags)) | VerificationFlags::SigPushOnly;
            let stepper = compare_step(flags, &checker);
            let mut res = StepResults::initial();
            let _ = RustInterpreter::verify(&pub_key[..], &sig[..], flags, &mut res, &stepper);

            if res.diverging_result != None {
                panic!("mismatched result: {:?}", res);
            }
        }
    }
}
