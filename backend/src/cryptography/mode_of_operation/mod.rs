use crate::cryptography::aes::AESKey;

mod cbc;
mod ctr;
mod ecb;
mod gcm;
#[cfg(test)]
mod tests;

/// Any mode of operation.
pub trait ModeOfOperation {}

/// Basic mode of operations without authentication and AAD (additional authenticated data).
pub trait BasicModeOfOperation: ModeOfOperation {
    fn encrypt<K: AESKey>(&self, key: &K, plaintext: &[u128]) -> Vec<u128>;
    fn decrypt<K: AESKey>(&self, key: &K, ciphertext: &[u128]) -> Vec<u128>;
}

/// Error struct that is used when the authentification fails when decrypting in Aead mode.
#[derive(Debug, PartialEq)]
pub struct AeadDecryptionTagMismatch;

/// Mode of operations with authentication and AEAD (authenticated encryption with associated data).
pub trait AeadModeOfOperation: ModeOfOperation {
    /// Encrypts *only* the plaintext and returns a tuple containing *only* the ciphertext
    /// and a tag (u128).
    fn encrypt<K: AESKey>(
        &self,
        key: &K,
        plaintext: &[u128],
        aad: Option<&[u128]>,
    ) -> (Vec<u128>, u128);
    /// Decrypts the ciphertext and authenticates that neither the ciphertext nor the AAD was
    /// changed. Returns a Result containing *only* the plaintext or an error if the tag does not
    /// match.
    fn decrypt<K: AESKey>(
        &self,
        key: &K,
        ciphertext: &[u128],
        aad: Option<&[u128]>,
        tag: u128,
    ) -> Result<Vec<u128>, AeadDecryptionTagMismatch>;
}
