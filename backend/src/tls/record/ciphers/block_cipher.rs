use crate::cryptography::aes::{AESKey128, AESKey256};
use crate::cryptography::block_cipher::AESCipher;
use crate::cryptography::hashing::copy_chunk_into_words_be;
use crate::cryptography::mode_of_operation::cbc::CBC;
use crate::cryptography::rng::rng;
use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::ciphers::cipher::TLSCipher;
use crate::tls::record::cryptographic_attributes::BlockCiphered;
use crate::tls::record::fragmentation::tls_ciphertext::{
    CipherType, GenericBlockCipher, GenericBlockCipherInner, TLSCiphertext,
};
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use rand::RngCore;
use std::fmt::Debug;
use std::io::{Error, ErrorKind, Result};

pub trait TLSBlockCipher: Debug + TLSCipher {
    fn encrypt_struct(
        &self,
        fragment: GenericBlockCipherInner,
        iv: &[u8],
    ) -> Result<BlockCiphered<GenericBlockCipherInner>>;
    fn decrypt_struct(
        &self,
        fragment: BlockCiphered<GenericBlockCipherInner>,
        con_state: &ConnectionState,
        iv: &[u8],
    ) -> Result<GenericBlockCipherInner>;
}

#[derive(Debug)]
enum AnyAESCipher {
    AES128(AESCipher<AESKey128, CBC>),
    AES256(AESCipher<AESKey256, CBC>),
}

#[derive(Debug)]
pub struct TLSAesCbcCipher {
    key: AnyAESCipher,
}

impl TLSAesCbcCipher {
    pub fn new(key: Vec<u8>) -> Result<Self> {
        let key = match key.len() {
            16 => {
                let mut words = [0u32; 4];
                copy_chunk_into_words_be!(key.as_slice(), words, u32);
                let key = AESKey128::new(words);
                AnyAESCipher::AES128(AESCipher::new(key))
            }
            32 => {
                let mut words = [0u32; 8];
                copy_chunk_into_words_be!(key.as_slice(), words, u32);
                let key = AESKey256::new(words);
                AnyAESCipher::AES256(AESCipher::new(key))
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Key has unsupported length: {}", key.len()),
                ))
            }
        };

        Ok(TLSAesCbcCipher { key })
    }
}

fn block_encrypt(
    cipher: &impl TLSBlockCipher,
    plaintext: TLSCompressed,
    con_state: &ConnectionState,
) -> Result<TLSCiphertext> {
    let mac = plaintext.generate_mac(con_state)?;

    let record_iv_len = *con_state.parameters.record_iv_length()? as usize;
    let mac_length = *con_state.parameters.mac_length()? as usize;
    let block_size = *con_state.parameters.block_length()? as usize;

    let mut iv = vec![0; record_iv_len];
    rng!().fill_bytes(iv.as_mut_slice());

    // TLSCiphertext.length = 1 + block_length + TLSCompressed.length + mac_length + padding_length
    // This length must be a multiple of block_length
    let length_without_padding = plaintext.fragment.len() + mac_length + 1;
    let padding_length = (block_size - (length_without_padding % block_size)) as u8;
    let padding = vec![padding_length; padding_length as usize];

    let inner = GenericBlockCipherInner {
        content: plaintext.fragment.into(),
        mac,
        padding,
        padding_length,
    };

    let generic_block_cipher = GenericBlockCipher {
        inner: cipher.encrypt_struct(inner, &iv)?,
        iv,
    };

    Ok(TLSCiphertext {
        content_type: plaintext.content_type,
        version: plaintext.version,
        fragment: CipherType::Block(generic_block_cipher),
    })
}

fn block_decrypt(
    cipher: &impl TLSBlockCipher,
    ciphertext: TLSCiphertext,
    con_state: &ConnectionState,
) -> Result<TLSCompressed> {
    let fragment = if let CipherType::Block(gcb) = ciphertext.fragment {
        gcb
    } else {
        return Err(Error::new(
            ErrorKind::Other,
            "Called TLSBlockCipher.decrypt on something that is not Block Cipher Encrypted",
        ));
    };

    let inner = cipher.decrypt_struct(fragment.inner, con_state, &fragment.iv)?;
    let mac = inner.mac;

    let fragment_bytes: VariableLengthVec<u8, 0, 17408> = inner.content.into();
    fragment_bytes.check_bounds()?;

    let tls_compressed = TLSCompressed {
        content_type: ciphertext.content_type,
        version: ciphertext.version,
        fragment: fragment_bytes,
    };

    let calculated_mac = tls_compressed.generate_mac(con_state)?;

    if mac == calculated_mac {
        Ok(tls_compressed)
    } else {
        Err(Error::new(ErrorKind::Other, "MAC mismatch"))
    }
}

impl TLSBlockCipher for TLSAesCbcCipher {
    fn encrypt_struct(
        &self,
        fragment: GenericBlockCipherInner,
        iv: &[u8],
    ) -> Result<BlockCiphered<GenericBlockCipherInner>> {
        let bytes = fragment.to_bytes();

        if bytes.len() % 16 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Fragment's bytes must be a multiple of 16",
            ));
        }

        let chunks: Vec<u128> = bytes
            .chunks(16)
            .map(|chunk| u128::from_be_bytes(chunk.try_into().unwrap()))
            .collect();

        let iv = u128::from_be_bytes(
            iv.try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "iv has incorrect length"))?,
        );

        let ciphertext = match &self.key {
            AnyAESCipher::AES128(aes128) => aes128.encrypt(chunks.as_slice(), &CBC { iv }),
            AnyAESCipher::AES256(aes256) => aes256.encrypt(chunks.as_slice(), &CBC { iv }),
        };

        let bytes: Vec<u8> = ciphertext
            .into_iter()
            .flat_map(|x| x.to_be_bytes())
            .collect();

        Ok(BlockCiphered::new(bytes))
    }

    fn decrypt_struct(
        &self,
        fragment: BlockCiphered<GenericBlockCipherInner>,
        con_state: &ConnectionState,
        iv: &[u8],
    ) -> Result<GenericBlockCipherInner> {
        let bytes = fragment.bytes;
        let mac_length = *con_state.parameters.mac_length()? as usize;

        if bytes.len() % 16 != 0 || bytes.len() < mac_length + 1 {
            return Err(Error::new(ErrorKind::Other, "invalid length"));
        }

        let chunks: Vec<u128> = bytes
            .chunks(16)
            .map(|c| u128::from_be_bytes(c.try_into().unwrap()))
            .collect();

        let iv = u128::from_be_bytes(
            iv.try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "iv has incorrect length"))?,
        );

        let plaintext = match &self.key {
            AnyAESCipher::AES128(aes128) => aes128.decrypt(chunks.as_slice(), &CBC { iv }),
            AnyAESCipher::AES256(aes256) => aes256.decrypt(chunks.as_slice(), &CBC { iv }),
        };

        let mut bytes: Vec<u8> = plaintext
            .into_iter()
            .flat_map(|x| x.to_be_bytes())
            .collect();
        let padding_length = bytes.pop().unwrap();

        if padding_length as usize > bytes.len() - mac_length {
            return Err(Error::new(ErrorKind::Other, "invalid padding length"));
        }

        let padding = bytes.split_off(bytes.len() - padding_length as usize);

        // padding must all contain padding_length
        if padding.iter().any(|&p| p != padding_length) {
            return Err(Error::new(ErrorKind::Other, "invalid padding"));
        }

        let expected_mac = bytes.split_off(bytes.len() - mac_length);
        let content = bytes;

        Ok(GenericBlockCipherInner {
            content,
            mac: expected_mac,
            padding,
            padding_length,
        })
    }
}

impl TLSCipher for TLSAesCbcCipher {
    fn encrypt(
        &self,
        plaintext: TLSCompressed,
        con_state: &ConnectionState,
    ) -> Result<TLSCiphertext> {
        block_encrypt(self, plaintext, con_state)
    }

    fn decrypt(
        &self,
        ciphertext: TLSCiphertext,
        con_state: &ConnectionState,
    ) -> Result<TLSCompressed> {
        block_decrypt(self, ciphertext, con_state)
    }
}
