use super::*;
use crate::cryptography::aes::*;
use crate::cryptography::block_cipher::AESCipher;

pub fn hex_to_u128_vec(hex: &str) -> Vec<u128> {
    (0..hex.len())
        .step_by(32)
        .map(|i| u128::from_str_radix(&hex[i..i + 32], 16).expect("Parsing error"))
        .collect()
}

pub fn test_encrypt<K: AESKey, M: ModeOfOperation>(
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

pub fn test_decrypt<K: AESKey, M: ModeOfOperation>(
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
