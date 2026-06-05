use crate::cryptography::pkcs1_v1_5;
use crate::cryptography::rsa::RSAPrivateKey;
use crate::tls::record::alert::{Alert, AlertResult};
use crate::tls::record::ciphers::cipher_suite::CipherConfig;
use crate::tls::record::cryptographic_attributes::PublicKeyEncrypted;
use crate::tls::record::key_exchange::pre_master_secret::{PreMasterSecret, PreMasterSecretRsa};
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::Debug;

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct EncryptedPreMasterSecret {
    pub pre_master_secret: PublicKeyEncrypted<PreMasterSecretRsa>,
}

impl EncryptedPreMasterSecret {
    pub fn decrypt_rsa(
        self,
        key: &RSAPrivateKey,
        cipher_config: Option<&CipherConfig>,
    ) -> AlertResult<PreMasterSecret> {
        self.pre_master_secret
            .decrypt(
                move |bytes| {
                    let padded = key
                        .decrypt_bytes(bytes.as_slice())
                        .map_err(|_| Alert::decrypt_error())?;

                    let message = pkcs1_v1_5::unpad(
                        &padded,
                        key.size_in_bytes(),
                        pkcs1_v1_5::PKCS1v1_5Mode::Encryption,
                    )
                    .map_err(|_| Alert::decrypt_error())?;

                    Ok(message)
                },
                cipher_config,
            )
            .map(Into::into)
    }
}
