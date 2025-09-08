use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug)]
pub enum ConnectionEnd {
    Server,
    Client,
}

#[derive(Debug)]
pub enum PRFAlgorithm {
    TlsPrfSha256,
}

#[derive(Debug)]
pub enum BulkCipherAlgorithm {
    Null,
    Rc4,
    TDes, // 3des, Triple Des
    Aes,
}

#[derive(Debug)]
pub enum CipherType {
    Stream,
    Block,
    Aead,
}

#[derive(Debug)]
pub enum MACAlgorithm {
    Null,
    HMacMd5,
    HMacSha1,
    HMacSha256,
    HMacSha384,
    HMacSha512,
}

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, ReadableFromStream, WritableToSink, Copy, Clone)]
pub enum CompressionMethod {
    Null = 0,
}

#[derive(Debug)]
pub struct SecurityParameters {
    pub entity: ConnectionEnd,
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
    pub fn new_empty(entity: ConnectionEnd) -> Self {
        SecurityParameters {
            entity,
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
}
