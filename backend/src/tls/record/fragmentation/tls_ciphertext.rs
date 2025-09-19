use crate::tls::connection::Connection;
use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::connection_state::security_parameters;
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::fragmentation::tls_plaintext::ContentType;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::ReadableFromStream;
use std::io::{Error, ErrorKind, Read, Result};

pub(crate) struct GenericStreamCipher {
    pub content: Vec<u8>,
    pub mac: Vec<u8>,
}

impl GenericStreamCipher {
    fn read(fragment: Vec<u8>, con_state: &ConnectionState) -> Result<Self> {
        let mac_length = con_state
            .parameters
            .mac_length
            .ok_or(Error::new(ErrorKind::Other, "MAC must be set by now"))?
            as usize;

        let mut content = fragment;
        let mac = content.split_off(content.len() - mac_length);

        Ok(Self { content, mac })
    }
}

pub(crate) struct GenericBlockCipher {}

impl GenericBlockCipher {
    fn read(fragment: Vec<u8>, con_state: &ConnectionState) -> Result<Self> {
        todo!()
    }
}

pub(crate) struct GenericAEADCipher {}

impl GenericAEADCipher {
    fn read(fragment: Vec<u8>, con_state: &ConnectionState) -> Result<Self> {
        todo!()
    }
}

pub(crate) enum CipherType {
    Stream(GenericStreamCipher),
    Block(GenericBlockCipher),
    Aead(GenericAEADCipher),
}

pub struct TLSCiphertext {
    pub(crate) content_type: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) fragment: CipherType,
}

/// Encrypts the given `TLSCompressed` to a `TLSCiphertext` using the cipher
/// specified in `con_state`. Also computes the `MAC` - if specified.
pub fn encrypt(compressed: TLSCompressed, con_state: &ConnectionState) -> Result<TLSCiphertext> {
    todo!()
}

impl TLSCiphertext {
    pub fn read_from_connection(connection: &mut Connection) -> Result<Self> {
        // Header contains 5 bytes
        let mut header_buf = [0u8; 5];
        connection.stream.read_exact(&mut header_buf)?;

        let mut iter = header_buf.into_iter();

        let content_type = ContentType::read(&mut iter)?;
        let version = ProtocolVersion::read(&mut iter)?;
        let length = u16::read(&mut iter)?;

        // length must not exceed 2^14 + 2048
        if length > 18432 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Length out of bounds: {}", length),
            ));
        }

        let mut fragment_buf = vec![0; length as usize];
        connection.stream.read_exact(fragment_buf.as_mut_slice())?;

        let current_read = &connection.connection_states.current_read;

        let fragment = match current_read.parameters.cipher_type.ok_or(Error::new(
            ErrorKind::Other,
            "Cipher type must be set by now",
        ))? {
            security_parameters::CipherType::Stream => {
                CipherType::Stream(GenericStreamCipher::read(fragment_buf, current_read)?)
            }
            security_parameters::CipherType::Block => {
                CipherType::Block(GenericBlockCipher::read(fragment_buf, current_read)?)
            }
            security_parameters::CipherType::Aead => {
                CipherType::Aead(GenericAEADCipher::read(fragment_buf, current_read)?)
            }
        };

        Ok(Self {
            content_type,
            version,
            fragment,
        })
    }

    pub fn decrypt(self, con_state: &mut ConnectionState) -> Result<TLSCompressed> {
        todo!()
    }
}
