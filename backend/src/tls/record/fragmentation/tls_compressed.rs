use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::connection_state::mac::MACAlgorithm;
use crate::tls::record::alert::Result;
use crate::tls::record::fragmentation::tls_ciphertext::{self, TLSCiphertext};
use crate::tls::record::fragmentation::tls_plaintext::{ContentType, TLSPlaintext};
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::WritableToSink;

pub struct TLSCompressed {
    pub(crate) content_type: ContentType,
    pub(crate) version: ProtocolVersion,
    /// Length of the following `.fragment`
    pub(crate) length: u16,
    pub(crate) fragment: VariableLengthVec<u8, 0, 17408>, // 2^14 + 1024
}

impl TLSCompressed {
    /// Decompressed this `TLSCompressed` into a `TLSPlaintext`. This function
    /// does the opposite of `TLSPlaintext.compress()`.
    pub fn decompress(self, con_state: &ConnectionState) -> Result<TLSPlaintext> {
        let compression = con_state.parameters.compression_algorithm()?;

        let fragment = compression.decompress(self.fragment)?;

        Ok(TLSPlaintext {
            content_type: self.content_type,
            version: self.version,
            length: fragment.len() as u16,
            fragment,
        })
    }

    /// Encrypts this `TLSCompressed` into a `TLSCiphertext`.
    pub fn encrypt(self, con_state: &ConnectionState) -> Result<TLSCiphertext> {
        tls_ciphertext::encrypt(self, con_state)
    }

    pub fn generate_mac(&self, con_state: &ConnectionState) -> Result<Vec<u8>> {
        let mac_alg = con_state.parameters.mac_algorithm()?;

        if matches!(mac_alg, MACAlgorithm::Null) {
            return Ok(Vec::new());
        }

        // length of seq_number (u64, 8 bytes) + .type (ContentType, 1 byte) +
        //  .version (ProtocolVersion, 2 bytes) + .length (u16, 2 bytes) = 13 bytes
        const MESSAGE_SIZE: usize = 13;

        // TODO: use iter here
        let mut message = Vec::with_capacity(MESSAGE_SIZE + self.fragment.len());

        message.extend_from_slice(&con_state.sequence_number.to_be_bytes()); // seq_number
        self.content_type.write(&mut message)?; // .type
        self.version.write(&mut message)?; // .version
        (self.fragment.len() as u16).write(&mut message)?; // .length
        message.extend_from_slice(self.fragment.as_slice()); // .fragment

        let write_key = con_state.mac_key.as_slice();
        Ok(mac_alg.hmac(write_key, message.as_slice()))
    }
}
