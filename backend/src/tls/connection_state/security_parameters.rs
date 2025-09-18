use super::mac::MACAlgorithm;
use super::prf::PRFAlgorithm;
use crate::tls::record::cipher_suite::CipherSuite;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, Clone, Copy)]
pub enum ConnectionEnd {
    Server,
    Client,
}

#[derive(Debug, Clone, Copy)]
pub enum BulkCipherAlgorithm {
    Null,
    Rc4,
    TDes, // 3des, Triple Des
    Aes,
}

#[derive(Debug, Clone, Copy)]
pub enum CipherType {
    Stream,
    Block,
    Aead,
}

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, ReadableFromStream, WritableToSink, Copy, Clone)]
pub enum CompressionMethod {
    Null = 0,
}

#[derive(Debug, Clone, Copy)]
pub struct SecurityParameters {
    pub entity: Option<ConnectionEnd>,
    pub prf_algorithm: Option<PRFAlgorithm>,
    pub bulk_cipher_algorithm: Option<BulkCipherAlgorithm>,
    pub cipher_type: Option<CipherType>,
    /// Number of bytes in encryption key.
    pub enc_key_length: Option<u8>,
    /// Number of bytes per block of encryption.
    pub block_length: Option<u8>,
    pub fixed_iv_length: Option<u8>,
    pub record_iv_length: Option<u8>,
    pub mac_algorithm: Option<MACAlgorithm>,
    /// Output length in bytes of MACAlgorithm
    pub mac_length: Option<u8>,
    pub mac_key_length: Option<u8>,
    pub compression_algorithm: Option<CompressionMethod>,
    pub master_secret: Option<[u8; 48]>,
    pub client_random: Option<[u8; 32]>,
    pub server_random: Option<[u8; 32]>,
}

impl SecurityParameters {
    pub fn new(entity: ConnectionEnd) -> Self {
        let mut p = Self::new_empty();
        p.entity = Some(entity);
        p
    }

    pub fn new_empty() -> Self {
        SecurityParameters {
            entity: None,
            prf_algorithm: None,
            bulk_cipher_algorithm: None,
            cipher_type: None,
            enc_key_length: None,
            block_length: None,
            fixed_iv_length: None,
            record_iv_length: None,
            mac_algorithm: None,
            mac_length: None,
            mac_key_length: None,
            compression_algorithm: None,
            master_secret: None,
            client_random: None,
            server_random: None,
        }
    }

    pub fn new_no_encryption(entity: ConnectionEnd) -> Self {
        let mut params = Self::new(entity);
        CipherSuite::TlsNullWithNullNull.set_security_params(&mut params);
        params
    }
}
