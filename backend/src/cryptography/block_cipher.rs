use crate::cryptography::aes::AESKey;
use crate::cryptography::mode_of_operation::*;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

pub struct AESCipher<K: AESKey, M: BasicModeOfOperation> {
    pub key: K,
    _marker: PhantomData<M>,
}

impl<K: AESKey, M: BasicModeOfOperation> Debug for AESCipher<K, M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AESCipher<{}> {{ key: {:?} }}",
            std::any::type_name::<M>().rsplit("::").next().unwrap(),
            self.key
        )
    }
}

pub struct AESCipherAead<K: AESKey, M: AeadModeOfOperation> {
    pub key: K,
    pub mode: M,
}

impl<K: AESKey, M: BasicModeOfOperation> AESCipher<K, M> {
    pub fn new(key: K) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }

    pub fn encrypt(&self, plaintext: &[u128], mode: &M) -> Vec<u128> {
        mode.encrypt(&self.key, plaintext)
    }

    pub fn decrypt(&self, ciphertext: &[u128], mode: &M) -> Vec<u128> {
        mode.decrypt(&self.key, ciphertext)
    }
}

impl<K: AESKey, M: AeadModeOfOperation> AESCipherAead<K, M> {
    pub fn new(key: K, mode: M) -> Self {
        Self { key, mode }
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> (Vec<u8>, u128) {
        self.mode.encrypt(&self.key, plaintext, aad)
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: u128,
    ) -> Result<Vec<u8>, AeadDecryptionTagMismatch> {
        self.mode.decrypt(&self.key, ciphertext, aad, tag)
    }
}
