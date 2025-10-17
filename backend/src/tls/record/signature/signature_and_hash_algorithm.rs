use super::hash_algorithm::HashAlgorithm;
use super::signature_algorithm::SignatureAlgorithm;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(ReadableFromStream, WritableToSink, Debug, Copy, Clone)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm,
}
