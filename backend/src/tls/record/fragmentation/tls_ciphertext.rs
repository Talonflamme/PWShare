use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::fragmentation::tls_plaintext::ContentType;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::{Sink, WritableToSink};
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::io::{Error, ErrorKind, Result};

#[derive(WritableToSink)]
struct GenericStreamCipher {

}

#[derive(WritableToSink)]
struct GenericBlockCipher {}

#[derive(WritableToSink)]
struct GenericAEADCipher {}

enum CipherType {
    Stream(GenericStreamCipher),
    Block(GenericBlockCipher),
    Aead(GenericAEADCipher),
}

impl WritableToSink for CipherType {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        match self {
            CipherType::Stream(gsc) => gsc.write(buffer)?,
            CipherType::Block(gbc) => gbc.write(buffer)?,
            CipherType::Aead(gac) => gac.write(buffer)?,
        }

        Ok(())
    }
}

pub struct TLSCiphertext {
    content_type: ContentType,
    version: ProtocolVersion,
}

/// Encrypts the given `TLSCompressed` to a `TLSCiphertext` using the cipher
/// specified in `con_state`. Also computes the `MAC` - if specified.
pub fn encrypt(compressed: TLSCompressed, con_state: &ConnectionState) -> Result<TLSCiphertext> {
    todo!()
}

impl TLSCiphertext {
    pub fn decrypt(self, con_state: &ConnectionState) -> Result<TLSCompressed> {
        todo!()
    }
}
