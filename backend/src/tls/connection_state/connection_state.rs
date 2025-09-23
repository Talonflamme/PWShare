use crate::tls::connection_state::security_parameters::{
    BulkCipherAlgorithm, ConnectionEnd, SecurityParameters,
};
use crate::tls::record::ciphers::cipher::TLSCipher;
use crate::tls::record::ciphers::{TLSAesCbcCipher, TLSNullCipher};
use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ConnectionState {
    pub parameters: SecurityParameters,
    // compression state
    // cipher state
    // MAC key
    /// Must be set to 0 when this connection state becomes the active state. Increments
    /// after each record is sent. The first record sent under this connection must
    /// use sequence number 0.
    pub sequence_number: u64,
    pub cipher: Box<dyn TLSCipher>,

    pub mac_key: Vec<u8>,
}

fn get_cipher(cipher_type: BulkCipherAlgorithm, key: Vec<u8>) -> Result<Box<dyn TLSCipher>> {
    match cipher_type {
        BulkCipherAlgorithm::Null => Ok(Box::new(TLSNullCipher {})),
        BulkCipherAlgorithm::Rc4 => Err(Error::new(ErrorKind::Other, "Not implemented")),
        BulkCipherAlgorithm::TDes => Err(Error::new(ErrorKind::Other, "Not implemented")),
        BulkCipherAlgorithm::Aes => Ok(Box::new(TLSAesCbcCipher::new(key)?)),
    }
}

impl ConnectionState {
    pub fn create_no_encryption(entity: ConnectionEnd) -> Self {
        Self {
            parameters: SecurityParameters::new_no_encryption(entity),
            sequence_number: 0,
            cipher: Box::new(TLSNullCipher {}),
            mac_key: Vec::new(),
        }
    }

    pub fn new(parameters: SecurityParameters) -> Result<Self> {
        let prf = parameters.prf_algorithm()?;

        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(parameters.server_random()?);
        seed[32..].copy_from_slice(parameters.client_random()?);
        let master_secret = parameters.master_secret()?;

        let mut key_block = prf.prf(master_secret, "key expansion", &seed);

        // key_block is partitioned like this:

        // client_write_MAC_key[mac_key_length]
        // server_write_MAC_key[mac_key_length]
        // client_write_key[enc_key_length]
        // server_write_key[enc_key_length]
        // client_write_IV[fixed_iv_length]
        // server_write_IV[fixed_iv_length]

        let entity = *parameters.entity()?;
        let mac_key_length = *parameters.mac_key_length()? as usize;
        let enc_key_length = *parameters.enc_key_length()? as usize;

        let mac_key: Vec<u8>;
        let enc_key: Vec<u8>;

        if entity == ConnectionEnd::Client {
            mac_key = key_block.by_ref().take(mac_key_length).collect(); // take client_write_MAC_key
            enc_key = key_block
                .by_ref()
                .skip(mac_key_length) // skip server_write_MAC_key
                .take(enc_key_length) // take client_write_key
                .collect();
        } else {
            mac_key = key_block
                .by_ref()
                .skip(mac_key_length) // skip client_write_MAC_key
                .take(mac_key_length) // take server_write_MAC_key
                .collect();
            enc_key = key_block
                .by_ref()
                .skip(enc_key_length) // skip client_write_key
                .take(enc_key_length) // take server_write_key
                .collect();
        }

        let bulk_cipher = *parameters.bulk_cipher_algorithm()?;

        Ok(Self {
            parameters,
            sequence_number: 0,
            cipher: get_cipher(bulk_cipher, enc_key)?,
            mac_key,
        })
    }
}
