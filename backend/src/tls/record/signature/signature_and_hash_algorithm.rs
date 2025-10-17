use pwshare_macros::{ReadableFromStream, WritableToSink};
use super::hash_algorithm::HashAlgorithm;
use super::signature_algorithm::SignatureAlgorithm;

#[derive(ReadableFromStream, WritableToSink, Debug, Copy, Clone)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm
}
