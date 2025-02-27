use std::ops::{Add, Neg, Sub};

use super::script_error::*;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ScriptNum(pub i64);

impl ScriptNum {
    const DEFAULT_MAX_NUM_SIZE: usize = 4;

    pub fn new(
        vch: &[u8],
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

    fn set_vch(vch: &[u8]) -> Result<i64, ScriptNumError> {
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
