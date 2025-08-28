use pwshare_macros::{ReadableFromStream, WritableToSink};
use crate::tls::record::handshake::hello::signature::SignatureAndHashAlgorithm;
use crate::tls::record::variable_length_vec::VariableLengthVec;

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct SignatureAlgorithmsExtension {
    pub supported_signature_algorithms: VariableLengthVec<SignatureAndHashAlgorithm, 2, 65334>
}