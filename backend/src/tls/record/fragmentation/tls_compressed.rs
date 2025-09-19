use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::fragmentation::tls_ciphertext::{self, TLSCiphertext};
use crate::tls::record::fragmentation::tls_plaintext::{ContentType, TLSPlaintext};
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use std::io::{Error, ErrorKind, Result};

pub struct TLSCompressed {
    pub(crate) content_type: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) fragment: VariableLengthVec<u8, 0, 17408>, // 2^14 + 1024
}

impl TLSCompressed {
    /// Decompressed this `TLSCompressed` into a `TLSPlaintext`. This function
    /// does the opposite of `TLSPlaintext.compress()`.
    pub fn decompress(self, con_state: &ConnectionState) -> Result<TLSPlaintext> {
        let compression = con_state
            .parameters
            .compression_algorithm
            .as_ref()
            .ok_or(Error::new(
                ErrorKind::Other,
                "No compression algorithm negotiated",
            ))?;

        Ok(TLSPlaintext {
            content_type: self.content_type,
            version: self.version,
            fragment: compression.decompress(self.fragment)?,
        })
    }

    /// Encrypts this `TLSCompressed` into a `TLSCiphertext`.
    pub fn encrypt(self, con_state: &ConnectionState) -> Result<TLSCiphertext> {
        tls_ciphertext::encrypt(self, con_state)
    }
}
