use crate::cryptography::mode_of_operation::*;
use crate::cryptography::aes::AESKey;

pub struct AESCipher<K: AESKey, M: ModeOfOperation> {
    pub key: K,
    pub mode: M
}

impl<K: AESKey, M: ModeOfOperation> AESCipher<K, M> {
    pub fn new(key: K, mode: M) -> Self {
        Self { key, mode }
    }
    
    pub fn encrypt(&self, plaintext: &[u128]) -> Vec<u128> {
        self.mode.encrypt(&self.key, plaintext)
    }
    
    pub fn decrypt(&self, ciphertext: &[u128]) -> Vec<u128> {
        self.mode.decrypt(&self.key, ciphertext)
    }
}
