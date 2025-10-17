use crate::tls::record::signature::SignatureAndHashAlgorithm;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct SignatureAlgorithmsExtension {
    pub supported_signature_algorithms: VariableLengthVec<SignatureAndHashAlgorithm, 2, 65334>
}