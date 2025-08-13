use super::*;
use crate::cryptography::block_cipher::{AESCipher, AESCipherAead};

pub fn hex_to_u128_vec(hex: &str) -> Vec<u128> {
    (0..hex.len())
        .step_by(32)
        .map(|i| u128::from_str_radix(&hex[i..i + 32], 16).expect("Parsing error"))
        .collect()
}

pub fn test_encrypt<K: AESKey, M: BasicModeOfOperation>(
    key: &str,
    plaintext: &str,
    expected: &str,
    mode: M,
) {
    let key = K::from_be_hex(key);
    let plain = hex_to_u128_vec(plaintext);
    let expected = hex_to_u128_vec(expected);

    let cipher = AESCipher::new(key, mode);
    let actual = cipher.encrypt(plain.as_slice());

    assert_eq!(actual, expected);
}


pub fn test_encrypt_aead<K: AESKey, M: AeadModeOfOperation>(
    key: &str,
    plaintext: &str,
    aad: Option<&str>,
    expected_ciphertext: &str,
    expected_tag: &str,
    mode: M,
) {
    let key = K::from_be_hex(key);
    let plain = hex_to_u128_vec(plaintext);
    let expected_ciphertext = hex_to_u128_vec(expected_ciphertext);
    let expected_tag = u128::from_str_radix(expected_tag, 16).expect("Parsing error");

    let mut vec = vec![];

    let aad = aad.map(|s| {
        vec = hex_to_u128_vec(s);
        vec.as_slice()
    });

    let cipher = AESCipherAead::new(key, mode);
    let (ciphertext, tag) = cipher.encrypt(plain.as_slice(), aad);

    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(tag, expected_tag);
}


pub fn test_decrypt<K: AESKey, M: BasicModeOfOperation>(
    key: &str,
    ciphertext: &str,
    expected: &str,
    mode: M,
) {
    let key = K::from_be_hex(key);
    let ciphertext = hex_to_u128_vec(ciphertext);
    let expected = hex_to_u128_vec(expected);

    let cipher = AESCipher::new(key, mode);
    let actual = cipher.decrypt(ciphertext.as_slice());

    assert_eq!(actual, expected);
}
