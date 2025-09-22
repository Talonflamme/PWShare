use std::marker::PhantomData;
use crate::cryptography::mode_of_operation::*;
use crate::cryptography::aes::AESKey;

#[derive(Debug)]
pub struct AESCipher<K: AESKey, M: BasicModeOfOperation> {
    pub key: K,
    _marker: PhantomData<M>
}

pub struct AESCipherAead<K: AESKey, M: AeadModeOfOperation> {
    pub key: K,
    pub mode: M
}

impl<K: AESKey, M: BasicModeOfOperation> AESCipher<K, M> {
    pub fn new(key: K) -> Self {
        Self { key, _marker: PhantomData }
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

    pub fn decrypt(&self, ciphertext: &[u8], aad: Option<&[u8]>, tag: u128) -> Result<Vec<u8>, AeadDecryptionTagMismatch> {
        self.mode.decrypt(&self.key, ciphertext, aad, tag)
    }
}
