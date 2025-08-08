use crate::cryptography::aes::AESKey;

mod ecb;
#[cfg(test)]
mod tests;
mod cbc;
mod ctr;

pub trait ModeOfOperation {
    fn encrypt<K: AESKey>(&self, key: &K, plaintext: &[u128]) -> Vec<u128>;
    fn decrypt<K: AESKey>(&self, key: &K, ciphertext: &[u128]) -> Vec<u128>;
}
