use std::{
    num::TryFromIntError,
    ops::{Add, Neg, Sub},
};

use super::script_error::*;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ScriptNum(pub i64);

impl ScriptNum {
    pub const ZERO: ScriptNum = ScriptNum(0);
    pub const ONE: ScriptNum = ScriptNum(1);

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
            if (vch.last().expect("not empty") & 0x7F) == 0 {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // then it would have conflicted with the sign bit if one
                // fewer byte were used, and so such encodings are minimal.
                // An example of this is +-255, which have minimal encodings
                // [0xff, 0x00] and [0xff, 0x80] respectively.
                if vch.len() <= 1 || (vch[vch.len() - 2] & 0x80) == 0 {
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
            // The code below was based on buggy C++ code, that produced the
            // "wrong" result for INT64_MIN. In that case we intentionally return
            // the result that the C++ code as compiled for zcashd (with `-fwrapv`)
            // originally produced on an x86_64 system.
            return vec![0, 0, 0, 0, 0, 0, 0, 128, 128];
        }

        let mut result = Vec::new();
        let neg = *value < 0;
        let mut absvalue = value.unsigned_abs();

        while absvalue != 0 {
            result.push((absvalue & 0xff).try_into().expect("fits in u8"));
            absvalue >>= 8;
        }

        // - If the most significant byte is >= 0x80 and the value is positive, push a
        //   new zero-byte to make the significant byte < 0x80 again.
        // - If the most significant byte is >= 0x80 and the value is negative, push a
        //   new 0x80 byte that will be popped off when converting to an integral.
        // - If the most significant byte is < 0x80 and the value is negative, add 0x80
        //   to it, since it will be subtracted and interpreted as a negative when
        //   converting to an integral.

        let result_back = result.last_mut().expect("not empty");
        if *result_back & 0x80 != 0 {
            result.push(if neg { 0x80 } else { 0 });
        } else if neg {
            *result_back |= 0x80;
        }

        result
    }

    fn set_vch(vch: &Vec<u8>) -> Result<i64, ScriptNumError> {
        match vch.last() {
            None => Ok(0),
            Some(vch_back) => {
                if *vch == vec![0, 0, 0, 0, 0, 0, 0, 128, 128] {
                    // Match the behaviour of the C++ code, which special-cased this
                    // encoding to avoid an undefined shift of a signed type by 64 bits.
                    return Ok(i64::MIN);
                };

                // Ensure defined behaviour (in Rust, left shift of `i64` by 64 bits
                // is an arithmetic overflow that may panic or give an unspecified
                // result). The above encoding of `i64::MIN` is the only allowed
                // 9-byte encoding.
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

impl From<i32> for ScriptNum {
    fn from(value: i32) -> Self {
        ScriptNum(value.into())
    }
}

impl From<i64> for ScriptNum {
    fn from(value: i64) -> Self {
        ScriptNum(value)
    }
}

impl From<u32> for ScriptNum {
    fn from(value: u32) -> Self {
        ScriptNum(value.into())
    }
}

impl From<u8> for ScriptNum {
    fn from(value: u8) -> Self {
        ScriptNum(value.into())
    }
}

/// TODO: This instance will be obsolete if we convert bool directly to a `Vec<u8>`, which is also
///       more efficient.
impl From<bool> for ScriptNum {
    fn from(value: bool) -> Self {
        ScriptNum(value.into())
    }
}

impl TryFrom<usize> for ScriptNum {
    type Error = TryFromIntError;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        value.try_into().map(ScriptNum)
    }
}

impl TryFrom<ScriptNum> for u16 {
    type Error = TryFromIntError;
    fn try_from(value: ScriptNum) -> Result<Self, Self::Error> {
        value.getint().try_into()
    }
}

impl TryFrom<ScriptNum> for u8 {
    type Error = TryFromIntError;
    fn try_from(value: ScriptNum) -> Result<Self, Self::Error> {
        value.getint().try_into()
    }
}

impl Add for ScriptNum {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(
            self.0
                .checked_add(other.0)
                .expect("caller should avoid overflow"),
        )
    }
}

impl Sub for ScriptNum {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(
            self.0
                .checked_sub(other.0)
                .expect("caller should avoid underflow"),
        )
    }
}

impl Neg for ScriptNum {
    type Output = Self;

    fn neg(self) -> Self {
        assert!(self.0 != i64::MIN);
        Self(-self.0)
    }
}
