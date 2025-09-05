use pwshare_macros::{ReadableFromStream, WritableToSink};

pub enum ConnectionEnd {
    Server,
    Client,
}

pub enum PRFAlgorithm {
    TlsPrfSha256,
}

pub enum BulkCipherAlgorithm {
    Null,
    Rc4,
    ThreeDes, // 3des
    Aes,
}

pub enum CipherType {
    Stream,
    Block,
    Aead,
}

pub enum MACAlgorithm {
    Null,
    HMacMd5,
    HMacSha1,
    HMacSha256,
    HMacSha384,
    HMacSha512,
}

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, ReadableFromStream, WritableToSink)]
pub enum CompressionMethod {
    Null = 0,
}

pub struct SecurityParameters {
    pub entity: ConnectionEnd,
    pub prf_algorithm: PRFAlgorithm,
    pub bulk_cipher_algorithm: BulkCipherAlgorithm,
    pub cipher_type: CipherType,
    pub enc_key_length: u8,
    pub block_length: u8,
    pub fixed_iv_length: u8,
    pub record_iv_length: u8,
    pub mac_algorithm: MACAlgorithm,
    pub mac_length: u8,
    pub mac_key_length: u8,
    pub compression_algorithm: CompressionMethod,
    pub master_secret: [u8; 48],
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
}
