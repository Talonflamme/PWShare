use crate::tls::record::signature::SignatureAndHashAlgorithm;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::Debug;

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct DigitallySigned {
    pub algorithm: SignatureAndHashAlgorithm,
    pub signature: VariableLengthVec<u8, 0, 65535>, // 2^16 - 1
}
