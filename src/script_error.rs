use std::num::TryFromIntError;

use secp256k1;

/// Things that can go wrong when constructing a `HashType` from bit flags.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InvalidHashType {
    /// Either or both of the two least-significant bits must be set.
    UnknownSignedOutputs,
    /// With v5 transactions, bits other than those specified for `HashType` must be 0. The `i32`
    /// includes only the bits that are undefined by `HashType`.
    ExtraBitsSet(i32),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScriptNumError {
    NegativeZero,
    NonMinimalEncoding,
    Overflow { max_num_size: usize, actual: usize },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ScriptError {
    // Ok = 0,
    UnknownError = 1,
    EvalFalse,
    OpReturn,

    // Max sizes
    ScriptSize,
    PushSize(Option<TryFromIntError>),
    OpCount,
    StackSize(Option<TryFromIntError>),
    SigCount(Option<TryFromIntError>),
    PubKeyCount(Option<TryFromIntError>),

    // Failed verify operations
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,

    // Logical/Format/Canonical errors
    BadOpcode(Option<u8>),
    DisabledOpcode(u8),
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,

    // OP_CHECKLOCKTIMEVERIFY
    NegativeLockTime,
    UnsatisfiedLockTime,

    // BIP62
    SigHashType(InvalidHashType),
    SigDER(secp256k1::Error),
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubKeyType,
    CleanStack,

    // softfork safeness
    DiscourageUpgradableNOPs,

    // extensions (these don’t exist in C++, and thus map to `UnknownError`)
    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },

    /// Corresponds to the `scriptnum_error` exception in C++.
    ScriptNumError(ScriptNumError),
}
