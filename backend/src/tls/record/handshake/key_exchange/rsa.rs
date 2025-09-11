use crate::tls::record::public_key_encrypted::PublicKeyEncrypted;
use crate::util::UintDisplay;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::{Debug, Formatter};
use crate::tls::record::protocol_version::ProtocolVersion;

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct EncryptedPreMasterSecret {
    pub pre_master_secret: PublicKeyEncrypted<PreMasterSecret>
}

#[derive(ReadableFromStream, WritableToSink)]
pub struct PreMasterSecret {
    client_version: ProtocolVersion,
    random: [u8; 46]
}

impl Debug for PreMasterSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", UintDisplay::hex(&self.random.as_slice()))
    }
}
