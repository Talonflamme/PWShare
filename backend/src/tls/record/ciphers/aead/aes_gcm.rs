use crate::cryptography::aes::{AESKey128, AESKey256};
use crate::cryptography::block_cipher::AESCipherAead;
use crate::cryptography::hashing::copy_chunk_into_words_be;
use crate::cryptography::mode_of_operation::gcm::GCM;
use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher::TLSCipher;
use crate::tls::record::cryptographic_attributes::AeadCiphered;
use crate::tls::record::fragmentation::tls_ciphertext::{
    CipherType, GenericAEADCipher, TLSCiphertext,
};
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::variable_length_vec::VariableLengthVec;

/// Computes the `additional_data` as specified in RFC 5246.
macro_rules! get_aad {
    ($plaintext:expr, $con_state:expr, $length:expr) => {{
        let mut aad = [0; 13];

        aad[..8].copy_from_slice(&$con_state.sequence_number.to_be_bytes()); // 8 bytes
        aad[8] = $plaintext.content_type as u8; // 1 byte
        aad[9] = $plaintext.version.major; // 1 byte
        aad[10] = $plaintext.version.minor; // 1 byte
        aad[11..].copy_from_slice(&$length.to_be_bytes()); // 2 bytes

        aad
    }};
}

macro_rules! impl_tls_aes_gcm {
    ($typ:ident, $key:ident) => {
        #[derive(Debug)]
        pub struct $typ {
            cipher: AESCipherAead<$key, GCM>,
        }

        impl $typ {
            pub fn new(key: Vec<u8>) -> Result<Self> {
                if key.len() != $key::BYTES {
                    return Err(Alert::internal_error(format!(
                        "Unexpected AES GCM key length: {}, expected: {}",
                        key.len(),
                        $key::BYTES
                    )));
                }

                let mut words = [0u32; $key::BYTES / 4];
                copy_chunk_into_words_be!(key.as_slice(), words, u32);
                let k = $key::new(words);
                Ok(Self {
                    cipher: AESCipherAead::new(k),
                })
            }
        }

        impl TLSCipher for $typ {
            fn encrypt(
                &self,
                plaintext: TLSCompressed,
                con_state: &ConnectionState,
            ) -> Result<TLSCiphertext> {
                // nonce consists of `salt` + `nonce_explicit`, with `salt = client_write_IV` (or server)
                let mut nonce = vec![0u8; 12];
                nonce[..4].copy_from_slice(&con_state.write_iv);
                let nonce_explicit = con_state.sequence_number.to_be_bytes();
                nonce[4..].copy_from_slice(&nonce_explicit);

                let aad = get_aad!(plaintext, con_state, plaintext.length);
                let plain_bytes = plaintext.fragment;

                let (ciphertext, auth_tag) =
                    self.cipher
                        .encrypt(&plain_bytes, Some(&aad), &GCM::new(nonce));

                let length = (ciphertext.len() + nonce_explicit.len() + 16) as u16; // 16 = len(auth_tag)

                let gac = GenericAEADCipher {
                    nonce_explicit: nonce_explicit.to_vec(),
                    content: AeadCiphered::new(ciphertext),
                    auth_tag,
                };

                Ok(TLSCiphertext {
                    version: plaintext.version,
                    content_type: plaintext.content_type,
                    length,
                    fragment: CipherType::Aead(gac),
                })
            }

            fn decrypt(
                &self,
                ciphertext: TLSCiphertext,
                con_state: &ConnectionState,
            ) -> Result<TLSCompressed> {
                let fragment = if let CipherType::Aead(a) = ciphertext.fragment {
                    a
                } else {
                    return Err(Alert::internal_error(
                        "TLSAeadCipher.decrypt called on something other than GenericAeadCipher",
                    ));
                };

                let mut nonce = vec![0; 12];
                nonce[..4].copy_from_slice(&con_state.write_iv); // salt
                nonce[4..].copy_from_slice(&fragment.nonce_explicit);

                let aad = get_aad!(ciphertext, con_state, ciphertext.length); // TODO: uses wrong .length

                let cipher_bytes = fragment.content.bytes;
                let auth_tag = fragment.auth_tag;

                let result = self
                    .cipher
                    .decrypt(&cipher_bytes, Some(&aad), auth_tag, &GCM::new(nonce))
                    .map_err(|_| Alert::bad_record_mac())?;

                let fragment_bytes: VariableLengthVec<u8, 0, 17408> = result.into();
                fragment_bytes.check_bounds()?;

                Ok(TLSCompressed {
                    content_type: ciphertext.content_type,
                    version: ciphertext.version,
                    length: fragment_bytes.len() as u16,
                    fragment: fragment_bytes,
                })
            }
        }
    };
}

impl_tls_aes_gcm!(TlsAes128Gcm, AESKey128);
impl_tls_aes_gcm!(TlsAes256Gcm, AESKey256);
