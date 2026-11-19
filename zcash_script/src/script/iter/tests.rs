use alloc::{vec, vec::Vec};

use crate::{
    interpreter::{Flags, NullSignatureChecker},
    script::{self, Code},
};

/// `sig_op_count` must match zcashd's `CScript::GetSigOpCount` even when the script contains
/// opcodes this crate buckets under `Disabled` -- in particular OP_CODESEPARATOR (0xab), which
/// is a normal, valid opcode in zcashd and must not stop the count.
#[test]
fn does_not_short_circuit_on_disabled_opcodes() {
    // OP_1 OP_CHECKMULTISIG: accurate counts the OP_N prefix (1); legacy counts 20.
    assert_eq!(Code(Vec::from([0x51u8, 0xae])).sig_op_count(true), 1);
    assert_eq!(Code(Vec::from([0x51u8, 0xae])).sig_op_count(false), 20);

    // OP_CODESEPARATOR (0xab) then OP_CHECKSIG: zcashd keeps counting -> 1.
    assert_eq!(Code(Vec::from([0xabu8, 0xac])).sig_op_count(true), 1);

    // OP_CAT (0x7e, truly disabled) then OP_CHECKSIG: zcashd still keeps counting -> 1.
    assert_eq!(Code(Vec::from([0x7eu8, 0xac])).sig_op_count(true), 1);

    // OP_CODESEPARATOR before 50 x OP_CHECKMULTISIG: each charged 20 (no OP_N prefix),
    // matching zcashd's GetSigOpCount(true) == 1000.
    let mut s = Vec::from([0xabu8]);
    s.extend([0xaeu8; 50]);
    assert_eq!(Code(s).sig_op_count(true), 1000);

    // A truncated push stops the count, like zcashd's GetOp returning false.
    assert_eq!(Code(Vec::from([0xacu8, 0x05, 0x01])).sig_op_count(true), 1);
}

/// zcashd's `CScript::GetSigOpCount` reads past a complete push of more than 520 bytes; only
/// evaluation rejects it.
#[test]
fn does_not_stop_at_pushes_over_520_bytes() {
    // OP_PUSHDATA2 of 521 bytes, OP_CHECKMULTISIG (20 in both modes: no OP_N before it),
    // then OP_1 OP_CHECKMULTISIG (1 accurate, 20 legacy).
    let mut s = Vec::from([0x4du8, 0x09, 0x02]);
    s.extend([0u8; 521]);
    s.extend([0xae, 0x51, 0xae]);
    assert_eq!(Code(s.clone()).sig_op_count(true), 21);
    assert_eq!(Code(s).sig_op_count(false), 40);
}

/// zcashd asserts that `P2SH` is set with `CleanStack`, so this is an error rather than a result to
/// match.
#[test]
fn clean_stack_requires_p2sh() {
    let script = script::Raw::from_raw_parts(vec![0x51], vec![]);
    assert_eq!(
        script.eval(Flags::CleanStack, &NullSignatureChecker()),
        Err((
            script::ComponentType::Redeem,
            script::Error::CleanStackWithoutP2SH
        ))
    );
    assert_eq!(
        script.eval(Flags::CleanStack | Flags::P2SH, &NullSignatureChecker()),
        Ok(true)
    );
}
