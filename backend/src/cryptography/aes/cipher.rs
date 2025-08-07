use crate::cryptography::aes::AESKey;

pub enum Mode {
    ECB,
    CBC,
    GCM
}

pub struct AESCipher<K: AESKey> {
    pub key: K,
}

impl<K: AESKey> AESCipher<K> {
    // pub fn new() -> Self {
    //
    // }
}
