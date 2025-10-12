use crate::cryptography::aes::{AESKey128, AESKey256};
use crate::cryptography::block_cipher::AESCipher;
use crate::cryptography::hashing::copy_chunk_into_words_be;
use crate::cryptography::mode_of_operation::cbc::CBC;
use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::block::{
    block_decrypt, block_encrypt, DecryptStructResult, TLSBlockCipher,
};
use crate::tls::record::ciphers::cipher::TLSCipher;
use crate::tls::record::cryptographic_attributes::BlockCiphered;
use crate::tls::record::fragmentation::tls_ciphertext::{GenericBlockCipherInner, TLSCiphertext};
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use std::fmt::Debug;

macro_rules! impl_tls_aes_cbc {
    ($typ:ident, $key:ident) => {
        #[derive(Debug)]
        pub struct $typ {
            cipher: AESCipher<$key, CBC>
        }

        impl $typ {
            pub fn new(key: Vec<u8>) -> Result<Self> {
                if key.len() != $key::BYTES {
                    // unknown key length, should not occur since those ciphers are not selected
                    return Err(Alert::internal_error(format!(
                        "Unexpected AES CBC key length: {}, expected: {}",
                        key.len(), $key::BYTES
                    )));
                }

                let mut words = [0u32; $key::BYTES / 4];
                copy_chunk_into_words_be!(key.as_slice(), words, u32);
                let k = $key::new(words);
                Ok(Self { cipher: AESCipher::new(k) })
            }
        }

        impl TLSBlockCipher for $typ {
            fn encrypt_struct(&self, fragment: GenericBlockCipherInner, iv: &[u8]) -> Result<BlockCiphered<GenericBlockCipherInner>> {
                let bytes = fragment.to_bytes();

                if bytes.len() % 16 != 0 {
                    return Err(Alert::internal_error(
                        "GenericBlockCipherInner's padding must result in a multiple of 128 bits for AES",
                    ));
                }

                let chunks: Vec<u128> = bytes
                    .chunks(16)
                    .map(|chunk| u128::from_be_bytes(chunk.try_into().unwrap()))
                    .collect();

                let iv = u128::from_be_bytes(
                    iv.try_into()
                        .map_err(|_| Alert::internal_error("bad IV length"))?,
                );

                let ciphertext = self.cipher.encrypt(chunks.as_slice(), &CBC { iv });

                let bytes: Vec<u8> = ciphertext
                    .into_iter()
                    .flat_map(|x| x.to_be_bytes())
                    .collect();

                Ok(BlockCiphered::new(bytes))
            }

            fn decrypt_struct(&self, fragment: BlockCiphered<GenericBlockCipherInner>, con_state: &ConnectionState, iv: &[u8]) -> Result<DecryptStructResult> {
                let bytes = fragment.bytes;
                let mac_length = *con_state.parameters.mac_length()? as usize;

                if bytes.len() % 16 != 0 || bytes.len() < mac_length + 1 {
                    return Err(Alert::bad_record_mac()); // also must be returned if length is not a multiple of block_size (128)
                }

                let chunks: Vec<u128> = bytes
                    .chunks(16)
                    .map(|c| u128::from_be_bytes(c.try_into().unwrap()))
                    .collect();

                let iv = u128::from_be_bytes(
                    iv.try_into().map_err(|_| Alert::bad_record_mac())?, // bad IV length
                );

                let plaintext = self.cipher.decrypt(chunks.as_slice(), &CBC { iv });

                let mut bytes: Vec<u8> = plaintext
                    .into_iter()
                    .flat_map(|x| x.to_be_bytes())
                    .collect();

                let padding_length = bytes.pop().unwrap();

                if padding_length as usize > bytes.len() - mac_length {
                    // assume 0 padding to prevent Timing Attack
                    return Ok(DecryptStructResult {
                        inner: GenericBlockCipherInner {
                            content: bytes,
                            mac: Vec::new(),     // field does not matter
                            padding: Vec::new(), // assume 0 padding
                            padding_length: 0,   // assume 0 padding
                        },
                        padding_error: Some(Alert::bad_record_mac()), // sent when padding values are incorrect
                    });
                }

                let padding = bytes.split_off(bytes.len() - padding_length as usize);

                // padding must all contain padding_length
                if padding.iter().any(|&p| p != padding_length) {
                    return Ok(DecryptStructResult {
                        inner: GenericBlockCipherInner {
                            content: bytes,
                            mac: Vec::new(),     // field does not matter
                            padding: Vec::new(), // assume 0 padding
                            padding_length: 0,   // assume 0 padding
                        },
                        padding_error: Some(Alert::bad_record_mac()), // sent when padding values are incorrect
                    });
                }

                let expected_mac = bytes.split_off(bytes.len() - mac_length);
                let content = bytes;

                Ok(DecryptStructResult {
                    inner: GenericBlockCipherInner {
                        content,
                        mac: expected_mac,
                        padding,
                        padding_length,
                    },
                    padding_error: None,
                })
            }
        }

        impl TLSCipher for $typ {
            fn encrypt(&self, plaintext: TLSCompressed, con_state: &ConnectionState) -> Result<TLSCiphertext> {
                block_encrypt(self, plaintext, con_state)
            }

            fn decrypt(&self, ciphertext: TLSCiphertext, con_state: &ConnectionState) -> Result<TLSCompressed> {
                block_decrypt(self, ciphertext, con_state)
            }
        }
    };
}

impl_tls_aes_cbc!(TlsAes128CbcCipher, AESKey128);
impl_tls_aes_cbc!(TlsAes256CbcCipher, AESKey256);
