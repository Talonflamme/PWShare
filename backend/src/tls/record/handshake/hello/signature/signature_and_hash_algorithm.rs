use pwshare_macros::{ReadableFromStream, WritableToSink};
use crate::tls::record::handshake::hello::signature::hash_algorithm::HashAlgorithm;
use crate::tls::record::handshake::hello::signature::signature_algorithm::SignatureAlgorithm;

#[derive(ReadableFromStream, WritableToSink, Debug, Copy, Clone)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm
}
