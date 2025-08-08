use super::*;
use crate::cryptography::aes::state::State;
use crate::cryptography::aes::tests::AESTestCaseOperation::{Decrypt, Encrypt};
use regex::Regex;
use std::fs;
use std::path::Path;
use std::str::FromStr;

fn single_mix_column_test<F>(input: &str, expected_output: &str, func: F)
where
    F: Fn(&mut [u8; 4]),
{
    assert_eq!(
        input.len(),
        8,
        "Unexpected length to convert string to array"
    );

    let mut inp = u32::from_str_radix(input, 16).unwrap().to_be_bytes();

    func(&mut inp);

    let output = format!("{:08x}", u32::from_be_bytes(inp));

    assert_eq!(expected_output, output);
}

enum AESTestCaseOperation {
    Encrypt,
    Decrypt,
}

struct AESTestCase {
    count: usize,
    operation: AESTestCaseOperation,
    aes: AES,
    is_monte_carlo: bool,
    iv: Option<String>,
    key: String,
    plaintext: String,
    ciphertext: String,
}

fn do_monte_carlo_test<K: AESKey>(case: AESTestCase) {
    let key = K::from_be_hex(case.key.as_str());
    let mut inp = u128::from_str_radix(
        match case.operation {
            Decrypt => &case.ciphertext,
            Encrypt => &case.plaintext,
        },
        16,
    )
    .unwrap();

    for _ in 0..10000 {
        let out = match case.operation {
            Decrypt => aes_decrypt(inp, &key),
            Encrypt => aes_encrypt(inp, &key),
        };
        inp = out;
    }

    let expected = u128::from_str_radix(
        match case.operation {
            Encrypt => &case.ciphertext,
            Decrypt => &case.plaintext,
        },
        16,
    )
    .unwrap();

    assert_eq!(inp, expected);
}

fn test_case<K: AESKey>(case: AESTestCase) {
    let key: K = K::from_be_hex(case.key.as_str());

    let plain = u128::from_str_radix(case.plaintext.as_str(), 16).unwrap();
    let cipher = u128::from_str_radix(case.ciphertext.as_str(), 16).unwrap();

    if case.is_monte_carlo {
        do_monte_carlo_test::<K>(case);
        return;
    }

    match case.operation {
        Encrypt => {
            let cipher_block = aes_encrypt(plain, &key);
            assert_eq!(
                cipher_block, cipher,
                "Incorrect encryption of count: {}.\nExpected: {:x}\nGot: {:x}",
                case.count, cipher, cipher_block
            );
        }
        Decrypt => {
            let plain_block = aes_decrypt(cipher, &key);
            assert_eq!(
                plain_block, plain,
                "Incorrect decryption of count: {}.\nExpected: {:x}\nGot:      {:x}",
                case.count, plain, plain_block
            );
        }
    }
}

fn test_cases(cases: impl Iterator<Item = AESTestCase>) {
    for case in cases {
        match case.aes {
            AES::AES128 => test_case::<AESKey128>(case),
            AES::AES192 => test_case::<AESKey192>(case),
            AES::AES256 => test_case::<AESKey256>(case),
        }
    }
}

fn test_encryption_from_file(filepath: impl AsRef<Path>) {
    let content = fs::read_to_string(filepath).expect("Could not read file");

    let length_re = Regex::new(r"(?i)# Key Length : (128|192|256)").unwrap();

    let m = length_re
        .captures(content.as_str())
        .expect("File does not contain Key Length definition");

    let is_monte_carlo = content.contains("# AESVS MCT test");

    let aes = match &m[1] {
        "128" => AES::AES128,
        "192" => AES::AES192,
        "256" => AES::AES256,
        _ => panic!(), // won't get here
    };

    // for encryption cases, the plaintext is the first line, then cipher
    let encryption_case_re = Regex::new(r"COUNT = (\d+)\r?\nKEY = ([\da-f]+)\r?\n(?:IV = ([\da-f]+)\r?\n)?PLAINTEXT = ([\da-f]+)\r?\nCIPHERTEXT = ([\da-f]+)").unwrap();

    let encryption_cases: Vec<_> = encryption_case_re.captures_iter(content.as_str()).collect();

    let mut cases = Vec::new();

    for encryption_case in encryption_cases {
        cases.push(AESTestCase {
            count: usize::from_str(&encryption_case[1]).unwrap(),
            operation: Encrypt,
            is_monte_carlo,
            aes,
            key: encryption_case[2].to_owned(),
            iv: encryption_case.get(3).map(|m| m.as_str().to_owned()),
            plaintext: encryption_case[4].to_owned(),
            ciphertext: encryption_case[5].to_owned(),
        });
    }

    test_cases(cases.into_iter());
}

fn test_decryption_from_file(filepath: impl AsRef<Path>) {
    let content = fs::read_to_string(filepath).expect("Could not read file");

    let re = Regex::new(r"(?i)# Key Length : (128|192|256)").unwrap();

    let m = re
        .captures(content.as_str())
        .expect("File does not contain Key Length definition");

    let is_monte_carlo = content.contains("# AESVS MCT test");

    let aes = match &m[1] {
        "128" => AES::AES128,
        "192" => AES::AES192,
        "256" => AES::AES256,
        _ => panic!(), // won't get here
    };

    // for decryption, it's the other way around: first cipher, then plain
    let decryption_case_re = Regex::new(r"COUNT = (\d+)\r?\nKEY = ([\da-f]+)\r?\n(?:IV = ([\da-f]+)\r?\n)?CIPHERTEXT = ([\da-f]+)\r?\nPLAINTEXT = ([\da-f]+)").unwrap();

    let decryption_cases: Vec<_> = decryption_case_re.captures_iter(content.as_str()).collect();

    let mut cases = Vec::new();

    for decryption_case in decryption_cases {
        cases.push(AESTestCase {
            count: usize::from_str(&decryption_case[1]).unwrap(),
            operation: Decrypt,
            is_monte_carlo,
            aes,
            key: decryption_case[2].to_owned(),
            iv: decryption_case.get(3).map(|m| m.as_str().to_owned()),
            ciphertext: decryption_case[4].to_owned(),
            plaintext: decryption_case[5].to_owned(),
        });
    }

    test_cases(cases.into_iter());
}

fn generic_key_expansion_test(key: &str, expected: &[&str]) {
    let key_vec: Vec<u32> = key
        .chars()
        .filter(|&c| c != ' ')
        .collect::<Vec<_>>()
        .chunks(8)
        .map(|chunk| u32::from_str_radix(chunk.iter().collect::<String>().as_str(), 16).unwrap())
        .collect();

    let expected_keys = expected
        .into_iter()
        .map(|&line| {
            let hex = line.chars().filter(|&c| c != ' ').collect::<String>();
            assert_eq!(hex.len(), 32); // 128-bit
            u128::from_str_radix(hex.as_str(), 16).unwrap()
        })
        .collect::<Vec<u128>>();

    match key_vec.len() {
        4 => key_expansion_test(
            AESKey128::new(key_vec.try_into().unwrap()),
            expected_keys,
        ),
        6 => key_expansion_test(
            AESKey192::new(key_vec.try_into().unwrap()),
            expected_keys,
        ),
        8 => key_expansion_test(
            AESKey256::new(key_vec.try_into().unwrap()),
            expected_keys,
        ),
        _ => panic!(
            "Unexpected length of key: `{}` with {} 32-bit words",
            key,
            key.len()
        ),
    }
}

fn key_expansion_test<K: AESKey>(k: K, expected: Vec<u128>) {
    let round_keys = k.generate_round_keys();

    assert_eq!(
        expected.len(),
        K::R,
        "Unexpected length of expected round keys"
    );

    for (i, (output, expected_output)) in
        round_keys.into_iter().zip(expected.into_iter()).enumerate()
    {
        assert_eq!(output, expected_output, "Key {} is unexpected", i);
    }
}

#[test]
fn test_key_expansion() {
    // AES-128
    generic_key_expansion_test(
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        &[
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63",
            "9b 98 98 c9 f9 fb fb aa 9b 98 98 c9 f9 fb fb aa",
            "90 97 34 50 69 6c cf fa f2 f4 57 33 0b 0f ac 99",
            "ee 06 da 7b 87 6a 15 81 75 9e 42 b2 7e 91 ee 2b",
            "7f 2e 2b 88 f8 44 3e 09 8d da 7c bb f3 4b 92 90",
            "ec 61 4b 85 14 25 75 8c 99 ff 09 37 6a b4 9b a7",
            "21 75 17 87 35 50 62 0b ac af 6b 3c c6 1b f0 9b",
            "0e f9 03 33 3b a9 61 38 97 06 0a 04 51 1d fa 9f",
            "b1 d4 d8 e2 8a 7d b9 da 1d 7b b3 de 4c 66 49 41",
            "b4 ef 5b cb 3e 92 e2 11 23 e9 51 cf 6f 8f 18 8e",
        ],
    );
    generic_key_expansion_test(
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
        &[
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
            "d6 aa 74 fd d2 af 72 fa da a6 78 f1 d6 ab 76 fe",
            "b6 92 cf 0b 64 3d bd f1 be 9b c5 00 68 30 b3 fe",
            "b6 ff 74 4e d2 c2 c9 bf 6c 59 0c bf 04 69 bf 41",
            "47 f7 f7 bc 95 35 3e 03 f9 6c 32 bc fd 05 8d fd",
            "3c aa a3 e8 a9 9f 9d eb 50 f3 af 57 ad f6 22 aa",
            "5e 39 0f 7d f7 a6 92 96 a7 55 3d c1 0a a3 1f 6b",
            "14 f9 70 1a e3 5f e2 8c 44 0a df 4d 4e a9 c0 26",
            "47 43 87 35 a4 1c 65 b9 e0 16 ba f4 ae bf 7a d2",
            "54 99 32 d1 f0 85 57 68 10 93 ed 9c be 2c 97 4e",
            "13 11 1d 7f e3 94 4a 17 f3 07 a7 8b 4d 2b 30 c5",
        ],
    );

    // AES-192
    generic_key_expansion_test(
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        &[
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            "00 00 00 00 00 00 00 00 62 63 63 63 62 63 63 63",
            "62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63",
            "9b 98 98 c9 f9 fb fb aa 9b 98 98 c9 f9 fb fb aa",
            "9b 98 98 c9 f9 fb fb aa 90 97 34 50 69 6c cf fa",
            "f2 f4 57 33 0b 0f ac 99 90 97 34 50 69 6c cf fa",
            "c8 1d 19 a9 a1 71 d6 53 53 85 81 60 58 8a 2d f9",
            "c8 1d 19 a9 a1 71 d6 53 7b eb f4 9b da 9a 22 c8",
            "89 1f a3 a8 d1 95 8e 51 19 88 97 f8 b8 f9 41 ab",
            "c2 68 96 f7 18 f2 b4 3f 91 ed 17 97 40 78 99 c6",
            "59 f0 0e 3e e1 09 4f 95 83 ec bc 0f 9b 1e 08 30",
            "0a f3 1f a7 4a 8b 86 61 13 7b 88 5f f2 72 c7 ca",
            "43 2a c8 86 d8 34 c0 b6 d2 c7 df 11 98 4c 59 70",
        ],
    );
    generic_key_expansion_test(
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17",
        &[
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
            "10 11 12 13 14 15 16 17 58 46 f2 f9 5c 43 f4 fe",
            "54 4a fe f5 58 47 f0 fa 48 56 e2 e9 5c 43 f4 fe",
            "40 f9 49 b3 1c ba bd 4d 48 f0 43 b8 10 b7 b3 42",
            "58 e1 51 ab 04 a2 a5 55 7e ff b5 41 62 45 08 0c",
            "2a b5 4b b4 3a 02 f8 f6 62 e3 a9 5d 66 41 0c 08",
            "f5 01 85 72 97 44 8d 7e bd f1 c6 ca 87 f3 3e 3c",
            "e5 10 97 61 83 51 9b 69 34 15 7c 9e a3 51 f1 e0",
            "1e a0 37 2a 99 53 09 16 7c 43 9e 77 ff 12 05 1e",
            "dd 7e 0e 88 7e 2f ff 68 60 8f c8 42 f9 dc c1 54",
            "85 9f 5f 23 7a 8d 5a 3d c0 c0 29 52 be ef d6 3a",
            "de 60 1e 78 27 bc df 2c a2 23 80 0f d8 ae da 32",
            "a4 97 0a 33 1a 78 dc 09 c4 18 c2 71 e3 a4 1d 5d",
        ],
    );

    // AES-256
    generic_key_expansion_test(
        "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
        &[
            "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
            "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
            "e8 e9 e9 e9 17 16 16 16 e8 e9 e9 e9 17 16 16 16",
            "0f b8 b8 b8 f0 47 47 47 0f b8 b8 b8 f0 47 47 47",
            "4a 49 49 65 5d 5f 5f 73 b5 b6 b6 9a a2 a0 a0 8c",
            "35 58 58 dc c5 1f 1f 9b ca a7 a7 23 3a e0 e0 64",
            "af a8 0a e5 f2 f7 55 96 47 41 e3 0c e5 e1 43 80",
            "ec a0 42 11 29 bf 5d 8a e3 18 fa a9 d9 f8 1a cd",
            "e6 0a b7 d0 14 fd e2 46 53 bc 01 4a b6 5d 42 ca",
            "a2 ec 6e 65 8b 53 33 ef 68 4b c9 46 b1 b3 d3 8b",
            "9b 6c 8a 18 8f 91 68 5e dc 2d 69 14 6a 70 2b de",
            "a0 bd 9f 78 2b ee ac 97 43 a5 65 d1 f2 16 b6 5a",
            "fc 22 34 91 73 b3 5c cf af 9e 35 db c5 ee 1e 05",
            "06 95 ed 13 2d 7b 41 84 6e de 24 55 9c c8 92 0f",
            "54 6d 42 4f 27 de 1e 80 88 40 2b 5b 4d ae 35 5e",
        ],
    );
    generic_key_expansion_test("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
                               &[
                                   "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
                                   "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
                                   "a5 73 c2 9f a1 76 c4 98 a9 7f ce 93 a5 72 c0 9c",
                                   "16 51 a8 cd 02 44 be da 1a 5d a4 c1 06 40 ba de",
                                   "ae 87 df f0 0f f1 1b 68 a6 8e d5 fb 03 fc 15 67",
                                   "6d e1 f1 48 6f a5 4f 92 75 f8 eb 53 73 b8 51 8d",
                                   "c6 56 82 7f c9 a7 99 17 6f 29 4c ec 6c d5 59 8b",
                                   "3d e2 3a 75 52 47 75 e7 27 bf 9e b4 54 07 cf 39",
                                   "0b dc 90 5f c2 7b 09 48 ad 52 45 a4 c1 87 1c 2f",
                                   "45 f5 a6 60 17 b2 d3 87 30 0d 4d 33 64 0a 82 0a",
                                   "7c cf f7 1c be b4 fe 54 13 e6 bb f0 d2 61 a7 df",
                                   "f0 1a fa fe e7 a8 29 79 d7 a5 64 4a b3 af e6 40",
                                   "25 41 fe 71 9b f5 00 25 88 13 bb d5 5a 72 1c 0a",
                                   "4e 5a 66 99 a9 f2 4f e0 7e 57 2b aa cd f8 cd ea",
                                   "24 fc 79 cc bf 09 79 e9 37 1a c2 3c 6d 68 de 36",
                               ]);
}

#[test]
fn test_mix_column() {
    single_mix_column_test("6347a2f0", "5de070bb", mix_column);
    single_mix_column_test("f20a225c", "9fdc589d", mix_column);
    single_mix_column_test("01010101", "01010101", mix_column);
    single_mix_column_test("2d26314c", "4d7ebdf8", mix_column);
    single_mix_column_test("d4d4d4d5", "d5d5d7d6", mix_column);
}

#[test]
fn test_inv_mix_column() {
    single_mix_column_test("5de070bb", "6347a2f0", inv_mix_column);
    single_mix_column_test("9fdc589d", "f20a225c", inv_mix_column);
    single_mix_column_test("01010101", "01010101", inv_mix_column);
    single_mix_column_test("4d7ebdf8", "2d26314c", inv_mix_column);
    single_mix_column_test("d5d5d7d6", "d4d4d4d5", inv_mix_column);
}

#[test]
fn test_shift_rows() {
    let mut state = State::new(0x0102030405060708090a0b0c0d0e0f10);

    // before:
    // 01 05 09 0d
    // 02 06 0a 0e
    // 03 07 0b 0f
    // 04 08 0c 10

    shift_rows(&mut state);

    // now it should be:
    // 01 05 09 0d
    // 06 0a 0e 02
    // 0b 0f 03 07
    // 10 04 08 0c

    let expected: u128 = 0x01060b10050a0f04090e03080d02070c;
    let actual: u128 = state.into();

    assert_eq!(actual, expected);
}

#[test]
fn test_inv_shift_rows() {
    let mut state = State::new(0x01060b10050a0f04090e03080d02070c);

    inv_shift_rows(&mut state);

    let actual: u128 = state.into();
    assert_eq!(actual, 0x0102030405060708090a0b0c0d0e0f10);
}

#[test]
fn test_add_round_key() {
    let initial: u128 = 0x0102030405060708090a0b0c0d0e0f10;

    let mut state = State::new(initial);
    let key: u128 = 0x10101010000100111100100110010110;

    add_round_key(&mut state, key);

    let expected = initial ^ key;
    let actual: u128 = state.into();

    assert_eq!(actual, expected);
}

#[test]
fn test_sub_bytes() {
    let mut state = State::new(0x0102030405060708090a0b0c0d0e0f10);

    // 01 05 09 0d
    // 02 06 0a 0e
    // 03 07 0b 0f
    // 04 08 0c 10

    sub_bytes(&mut state);

    // 7c 6b 01 d7
    // 77 6f 67 ab
    // 7b c5 2b 76
    // f2 30 fe ca

    let actual: u128 = state.into();
    let expected: u128 = 0x7c777bf26b6fc53001672bfed7ab76ca;

    assert_eq!(actual, expected);
}

#[test]
fn test_inv_sub_bytes() {
    let mut state = State::new(0x7c777bf26b6fc53001672bfed7ab76ca);
    inv_sub_bytes(&mut state);
    let actual: u128 = state.into();
    let expected: u128 = 0x0102030405060708090a0b0c0d0e0f10;

    assert_eq!(actual, expected);
}

#[test]
fn encryption128() {
    test_encryption_from_file("test_vectors/ECBGFSbox128.rsp");
    test_encryption_from_file("test_vectors/test128.rsp");
}

#[test]
fn decryption128() {
    test_decryption_from_file("test_vectors/ECBGFSbox128.rsp");
    test_decryption_from_file("test_vectors/test128.rsp");
}

#[test]
fn encryption192() {
    test_encryption_from_file("test_vectors/ECBGFSbox192.rsp");
    test_encryption_from_file("test_vectors/test192.rsp");
}

#[test]
fn decryption192() {
    test_decryption_from_file("test_vectors/ECBGFSbox192.rsp");
    test_decryption_from_file("test_vectors/test192.rsp");
}

#[test]
fn encryption256() {
    test_encryption_from_file("test_vectors/ECBGFSbox256.rsp");
    test_encryption_from_file("test_vectors/test256.rsp");
}

#[test]
fn decryption256() {
    test_decryption_from_file("test_vectors/ECBGFSbox256.rsp");
    test_decryption_from_file("test_vectors/test256.rsp");
}
