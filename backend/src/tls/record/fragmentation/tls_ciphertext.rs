use crate::tls::connection::Connection;
use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::connection_state::security_parameters;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::cryptographic_attributes::{AeadCiphered, BlockCiphered, StreamCiphered};
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::fragmentation::tls_plaintext::ContentType;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use std::io::Read;

pub(crate) struct GenericStreamCipher {
    pub content: Vec<u8>,
    pub mac: Vec<u8>,
}

impl GenericStreamCipher {
    pub fn read(fragment: Vec<u8>, con_state: &ConnectionState) -> Result<Self> {
        let mac_length = *con_state.parameters.mac_length()? as usize;

        let mut content = fragment;
        let mac = content.split_off(content.len() - mac_length);

        Ok(Self { content, mac })
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut content = self.content;
        let mut mac = self.mac;

        content.append(&mut mac);
        content
    }
}

pub(crate) struct GenericBlockCipher {
    pub iv: Vec<u8>,
    pub inner: BlockCiphered<GenericBlockCipherInner>,
}

impl GenericBlockCipher {
    fn read(mut fragment: Vec<u8>, con_state: &ConnectionState) -> Result<Self> {
        let record_iv_length = *con_state.parameters.record_iv_length()? as usize;

        let block_ciphered = fragment.split_off(record_iv_length);
        let iv = fragment;

        Ok(Self {
            iv,
            inner: BlockCiphered::new(block_ciphered),
        })
    }
}

impl WritableToSink for GenericBlockCipher {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        buffer.extend_from_slice(self.iv.as_slice());
        buffer.extend_from_slice(self.inner.bytes.as_slice());
        Ok(())
    }
}

pub(crate) struct GenericBlockCipherInner {
    pub content: Vec<u8>,
    pub mac: Vec<u8>,
    pub padding: Vec<u8>,
    pub padding_length: u8,
}

impl GenericBlockCipherInner {
    pub fn to_bytes(mut self) -> Vec<u8> {
        let mut result =
            Vec::with_capacity(self.content.len() + self.mac.len() + self.padding.len() + 1);
        result.append(&mut self.content);
        result.append(&mut self.mac);
        result.append(&mut self.padding);
        result.push(self.padding_length);
        result
    }
}

pub(crate) struct GenericAEADCipher {
    pub nonce_explicit: Vec<u8>,
    pub content: AeadCiphered<Vec<u8>>,
    pub auth_tag: u128,
}

impl GenericAEADCipher {
    fn read(mut fragment: Vec<u8>, con_state: &ConnectionState) -> Result<Self> {
        let record_iv_length = *con_state.parameters.record_iv_length()? as usize;

        if fragment.len() < record_iv_length + 16 {
            Err(Alert::bad_record_mac())
        } else {
            let mut content = fragment.split_off(record_iv_length);
            let auth_tag = content.split_off(content.len() - 16);
            let auth_tag = u128::from_be_bytes(auth_tag.try_into().unwrap());
            Ok(Self {
                nonce_explicit: fragment,
                content: AeadCiphered::new(content),
                auth_tag,
            })
        }
    }
}

impl WritableToSink for GenericAEADCipher {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        buffer.extend_from_slice(&self.nonce_explicit);
        buffer.extend_from_slice(&self.content.bytes);
        Ok(())
    }
}

pub(crate) enum CipherType {
    Stream(StreamCiphered<GenericStreamCipher>),
    Block(GenericBlockCipher),
    Aead(GenericAEADCipher),
}

impl WritableToSink for CipherType {
    fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        // here, we do not include a discriminant before, since
        // the variant depends on SecurityParameters.cipher_type
        match self {
            CipherType::Stream(gsc) => buffer.extend_from_slice(&gsc.bytes),
            CipherType::Block(gbc) => gbc.write(buffer)?,
            CipherType::Aead(gac) => gac.write(buffer)?,
        }

        Ok(())
    }
}

pub struct TLSCiphertext {
    pub(crate) content_type: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) length: u16, 
    pub(crate) fragment: CipherType,
}

/// Encrypts the given `TLSCompressed` to a `TLSCiphertext` using the cipher
/// specified in `con_state`. Also computes the `MAC` - if specified.
pub fn encrypt(compressed: TLSCompressed, con_state: &ConnectionState) -> Result<TLSCiphertext> {
    con_state.cipher.encrypt(compressed, con_state)
}

impl TLSCiphertext {
    pub fn read_from_connection(connection: &mut Connection) -> Result<Self> {
        // Header contains 5 bytes
        let mut header_buf = [0u8; 5];
        connection
            .stream
            .read_exact(&mut header_buf)
            .map_err(|e| Alert::internal_error(format!("Failed reading bytes: {}", e)))?;

        let mut iter = header_buf.into_iter();

        let content_type = ContentType::read(&mut iter)?;
        let version = ProtocolVersion::read(&mut iter)?;
        let length = u16::read(&mut iter)?;

        // length must not exceed 2^14 + 2048
        if length > 18432 {
            return Err(Alert::record_overflow()); // message too large
        }

        let mut fragment_buf = vec![0; length as usize];
        connection
            .stream
            .read_exact(fragment_buf.as_mut_slice())
            .map_err(|e| Alert::internal_error(format!("Failed reading bytes: {}", e)))?;

        let current_read = &connection.connection_states.current_read;

        let fragment = match current_read.parameters.cipher_type()? {
            security_parameters::CipherType::Stream => {
                CipherType::Stream(StreamCiphered::new(fragment_buf))
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
            length,
            fragment,
        })
    }

    pub fn write(&self, buffer: &mut impl Sink<u8>) -> Result<()> {
        self.content_type.write(buffer)?; // .type
        self.version.write(buffer)?; // .version

        let mut frag_buffer: Vec<u8> = Vec::new();
        self.fragment.write(&mut frag_buffer)?;

        let length = frag_buffer.len();

        if length > 18432 {
            return Err(Alert::internal_error(
                "Length of TLSCiphertext out of bounds",
            ));
        }

        let length = length as u16;
        length.write(buffer)?; // .length
        buffer.append(frag_buffer); // .fragment

        Ok(())
    }

    pub fn decrypt(self, con_state: &ConnectionState) -> Result<TLSCompressed> {
        con_state.cipher.decrypt(self, con_state)
    }
}
