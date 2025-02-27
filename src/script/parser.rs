use crate::script;

/// A prism between a Zcash Script byte stream and a Rust representation.
pub trait Parsable {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), script::Error>
    where
        Self: Sized;
}
