use crate::cryptography::aes::{AESKey128, AESKey256};
use crate::cryptography::block_cipher::AESCipher;
use crate::cryptography::hashing::copy_chunk_into_words_be;
use crate::cryptography::mode_of_operation::cbc::CBC;
use crate::cryptography::rng::rng;
use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher::TLSCipher;
use crate::tls::record::cryptographic_attributes::BlockCiphered;
use crate::tls::record::fragmentation::tls_ciphertext::{
    CipherType, GenericBlockCipher, GenericBlockCipherInner, TLSCiphertext,
};
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use rand::RngCore;
use std::fmt::Debug;

trait TLSBlockCipher: Debug + TLSCipher {
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
    ) -> Result<DecryptStructResult>;
}

/// We use a different struct as this result in order to prevent a timing attack based on
/// invalid padding. This way, even when the padding is incorrect, operations like computing
/// the MAC is still performed to have constant time. In that case, `padding_error` will be Some.
struct DecryptStructResult {
    inner: GenericBlockCipherInner,
    /// `Some` if the padding was incorrect, `None` otherwise.
    padding_error: Option<Alert>,
}

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
        return Err(Alert::internal_error(
            "TLSBlockCipher.decrypt called on something other than GenericBlockCipher",
        ));
    };

    // even when padding is invalid, we still compute the mac and do all other
    // operations to prevent a timing attack
    let DecryptStructResult {
        inner,
        padding_error,
    } = cipher.decrypt_struct(fragment.inner, con_state, &fragment.iv)?;

    let mac = inner.mac;

    let fragment_bytes: VariableLengthVec<u8, 0, 17408> = inner.content.into();
    fragment_bytes.check_bounds()?;

    let tls_compressed = TLSCompressed {
        content_type: ciphertext.content_type,
        version: ciphertext.version,
        fragment: fragment_bytes,
    };

    let calculated_mac = tls_compressed.generate_mac(con_state)?;

    if let Some(padding_error) = padding_error {
        Err(padding_error)
    } else if mac == calculated_mac {
        Ok(tls_compressed)
    } else {
        Err(Alert::bad_record_mac())
    }
}
