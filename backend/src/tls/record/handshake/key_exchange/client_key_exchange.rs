use pwshare_macros::{ReadableFromStream, WritableToSink};
use crate::tls::record::handshake::key_exchange::rsa::EncryptedPreMasterSecret;

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ClientKeyExchange {
    pub exchange_keys: EncryptedPreMasterSecret,
}
