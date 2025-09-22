use super::mac::MACAlgorithm;
use super::prf::PRFAlgorithm;
use crate::tls::connection_state::compression_method::CompressionMethod;
use crate::tls::record::ciphers::cipher_suite::CipherSuite;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

macro_rules! impl_getters {
    ($struct: ident, { $($field: ident : $ty:ty),* $(,)? }) => {
        impl $struct {
            $(
                pub fn $field (&self) -> std::io::Result<&$ty> {
                    self.$field.as_ref().ok_or(
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            concat!(stringify!($field), " must not be None")
                        )
                    )
                }
            )*
        }
    }
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

impl_getters!(SecurityParameters, {
    entity: ConnectionEnd,
    prf_algorithm: PRFAlgorithm,
    bulk_cipher_algorithm: BulkCipherAlgorithm,
    cipher_type: CipherType,
    enc_key_length: u8,
    block_length: u8,
    fixed_iv_length: u8,
    record_iv_length: u8,
    mac_algorithm: MACAlgorithm,
    mac_length: u8,
    mac_key_length: u8,
    compression_algorithm: CompressionMethod,
    master_secret: [u8; 48],
    client_random: [u8; 32],
    server_random: [u8; 32],
});

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
        params.compression_algorithm = Some(CompressionMethod::Null);
        CipherSuite::TlsNullWithNullNull.set_security_params(&mut params);
        params
    }
}
