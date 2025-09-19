use crate::tls::record::variable_length_vec::VariableLengthVec;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::io::Result;

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, ReadableFromStream, WritableToSink, Copy, Clone)]
pub enum CompressionMethod {
    Null = 0,
}

impl CompressionMethod {
    /// Compresses the uncompressed `fragment` into the compressed `fragment`.
    /// The uncompressed `fragment` of `TLSPlaintext` can have a max. length of 2^14 bytes.
    /// The compressed fragment of `TLSCompressed` may add up to 1024 bytes.
    pub fn compress(
        &self,
        uncompressed: VariableLengthVec<u8, 0, 16384>, // 16384 = 2^14
    ) -> Result<VariableLengthVec<u8, 0, 17408>> {
        // 17408 = 2^14 + 1024
        match self {
            CompressionMethod::Null => {
                // null is an identity function
                Ok(uncompressed.try_into().unwrap()) // can't fail since the target has a higher range
            }
        }
    }

    pub fn decompress(
        &self,
        compressed: VariableLengthVec<u8, 0, 17408>,
    ) -> Result<VariableLengthVec<u8, 0, 16384>> {
        match self {
            CompressionMethod::Null => Ok(compressed.try_into().expect("Null.decompress()/compress() should be an identity function and return the exact vector")),
        }
    }
}
