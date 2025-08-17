use crate::cryptography::aes::galois_mul::gmul128;
use crate::cryptography::aes::{aes_encrypt, AESKey};
use crate::cryptography::mode_of_operation::{
    AeadDecryptionTagMismatch, AeadModeOfOperation, ModeOfOperation,
};

/// The Galois/Counter Mode (GCM) is a mode of operations for symmetric-key block ciphers. It not
/// encrypts data but also authenticates it with optional additional authenticated data (AAD).
pub struct GCM {
    /// The nonce is a value used exactly once. It will be appended with the counter to create
    /// a unique 128-bit number for each plaintext block (independent of block values). This
    /// is safe as long as the `(nonce, counter)` pair is never used again. It can be of any
    /// length (even more than 16 bytes or fewer).
    nonce: Vec<u8>,
}

impl GCM {
    pub fn new(nonce: Vec<u8>) -> GCM {
        GCM { nonce }
    }

    pub fn from_nonce_string(nonce: &str) -> GCM {
        assert_eq!(nonce.len() % 2, 0);

        let iv = (0..nonce.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&nonce[i..i + 2], 16).expect("Parse error"))
            .collect();

        GCM { nonce: iv }
    }

    fn g_hash_with_initial(h: u128, bits: &[u128], mut initial: u128) -> u128 {
        for block in bits {
            initial = gmul128(block ^ initial, h);
        }
        initial
    }

    /// GHASH is defined as:<br>
    /// GHASH(H, A, C) = X<sub>m+n+1</sub><br>
    /// where:<br>
    /// `H = E(0^128)`, the encryption of 128 zero bits<br>
    /// `A`, the data which is only authenticated, not encrypted, also `AAD`<br>
    /// `C`, the ciphertext<br>
    /// `m = len(A) / 128`, the amount of 128-bit blocks in `A` (rounded up)<br>
    /// `n = len(C) / 128`, the amount of 128-bit blocks in `C` (rounded up)<br>
    fn g_hash(h: u128, a: &[u8], c: &[u8]) -> u128 {
        // This is where the padded information is stored.
        // The 128 block that is stored here is len(A) || len(C) of the 64-bit representations
        // of the bit length of A and C. Since `a` and `c` contain bytes, we multiply the amount
        // bytes with 8 (or left-shift 3).
        let last_block_value = ((a.len() as u128) << 67) | ((c.len() as u128) << 3);

        fn convert_to_u128(slice: &[u8], words: &mut Vec<u128>) {
            let (chunks, rem) = slice.as_chunks::<16>();
            words.extend(chunks.iter().map(|&chunk| u128::from_be_bytes(chunk)));

            if rem.len() != 0 {
                let mut buffer = [0; 16];
                buffer[..rem.len()].copy_from_slice(rem);
                words.push(u128::from_be_bytes(buffer));
            }
        }

        // convert a and c into 128 words
        let capacity = a.len() / 16
            + (a.len() % 16 != 0) as usize
            + c.len() / 16
            + (c.len() % 16 != 0) as usize;

        let mut words = Vec::with_capacity(capacity);
        convert_to_u128(a, &mut words);
        convert_to_u128(c, &mut words);

        let mut hash = Self::g_hash_with_initial(h, words.as_slice(), 0);
        hash = Self::g_hash_with_initial(h, &[last_block_value], hash);
        hash
    }

    fn calculate_counter0(&self, h: u128) -> u128 {
        let len = self.nonce.len() * 8;

        if len == 96 {
            // nonce is 96-bit
            let mut buffer = [0; 16];
            buffer[..12].copy_from_slice(self.nonce.as_slice());
            // nonce || 0^31 || 1
            u128::from_be_bytes(buffer) | 1
        } else {
            let (chunks, remainder) = self.nonce.as_chunks::<16>();

            let mut result: Vec<u128> =
                chunks.iter().map(|&arr| u128::from_be_bytes(arr)).collect();

            if !remainder.is_empty() {
                let mut buf = [0; 16];
                buf[..remainder.len()].copy_from_slice(remainder);
                result.push(u128::from_be_bytes(buf));
            }

            let len: u128 = self.nonce.len() as u128 * 8;

            result.push(len);

            GCM::g_hash_with_initial(h, result.as_slice(), 0)
        }
    }

    /// Encrypts/decrypts the plaintext/ciphertext by XORing the encrypted output
    /// of the counter with the input. Bytes in the masks (encryption of counter) that
    /// don't have corresponding bytes in plain-/ciphertext are unused.
    ///
    /// `counter0`: the counter0 or J0 number which is *not* used to encrypt the first
    /// block. This counter will be incremented with 1 for each 128-bit block. The first
    /// block will hence be XORed with the result of `counter0 + 1`.
    fn encrypt_ctr<K: AESKey>(key: &K, plaintext: &[u8], counter0: u128) -> Vec<u8> {
        let (chunks, remainder) = plaintext.as_chunks::<16>();
        let mut res = Vec::with_capacity(plaintext.len());

        /// xor the bytes of the mask with the bytes of chunk (big-endian, first byte is
        /// most significant). If chunk has less than 16 bytes, the remaining bytes of mask will
        /// be unused.
        fn apply_mask_to_chunk(mask: u128, chunk: &[u8], res: &mut Vec<u8>) {
            for (i, byte) in chunk.iter().enumerate() {
                let masking_byte = (mask >> (120 - 8 * i)) & 0xff;
                let cipher_byte = (*byte) ^ (masking_byte as u8);
                res.push(cipher_byte);
            }
        }

        // first block is encrypt with `counter0 + 1`
        let mut counter = counter0 + 1;

        for chunk in chunks {
            let mask = aes_encrypt(counter, key);
            counter += 1;
            apply_mask_to_chunk(mask, chunk, &mut res);
        }

        let mask = aes_encrypt(counter, key);
        apply_mask_to_chunk(mask, remainder, &mut res);

        res
    }
}

impl ModeOfOperation for GCM {}

impl AeadModeOfOperation for GCM {
    fn encrypt<K: AESKey>(&self, key: &K, plaintext: &[u8], aad: Option<&[u8]>) -> (Vec<u8>, u128) {
        let zeros: u128 = 0x0;
        // key dependant point H = E(0^128)
        let h = aes_encrypt(zeros, key);

        let counter0 = self.calculate_counter0(h);

        let masking_key = aes_encrypt(counter0, key);

        let ciphertext = GCM::encrypt_ctr(key, plaintext, counter0);

        let mut tag = Self::g_hash(h, aad.unwrap_or(&[]), ciphertext.as_slice());
        tag ^= masking_key;

        (ciphertext, tag)
    }

    fn decrypt<K: AESKey>(
        &self,
        key: &K,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: u128,
    ) -> Result<Vec<u8>, AeadDecryptionTagMismatch> {
        // key dependant point H = E(0^128)
        let h = aes_encrypt(0, key);
        let counter0 = self.calculate_counter0(h);
        let masking_key = aes_encrypt(counter0, key);

        let calculated_tag = Self::g_hash(h, aad.unwrap_or(&[]), ciphertext) ^ masking_key;

        if tag != calculated_tag {
            return Err(AeadDecryptionTagMismatch);
        }

        // encryption and decryption are the same
        let plaintext = GCM::encrypt_ctr(key, ciphertext, counter0);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptography::aes::{AESKey128, AESKey192, AESKey256};
    use crate::cryptography::mode_of_operation::gcm::GCM;
    use crate::cryptography::mode_of_operation::tests::{test_decrypt_aead, test_encrypt_aead};
    use crate::cryptography::mode_of_operation::AeadDecryptionTagMismatch;
    #[test]
    fn gcm_encrypt_128() {
        test_encrypt_aead::<AESKey128, GCM>(
            "af0918cd2a119a5853ebeadfc9cbdd8c",
            "76d46d9170d484528f8ccf702469fe64106a49253224fd4f36b1eba9efc1edb980d1351a1963e39fba1043dfccb99b5fe30a10183707253fe53e4626e67aa0cd",
            Some("ee88846a084115bc1f4e65e9a6dbed4527ab7da1a5a1783147882feecfa1e266"),
            "7fb6a3c0648b543588a1ae542e3dfca4e32b3b8ebf0cf935522e5f3bb29bc94d035d827208111720d14e1d54581ec1a8a6cc816f13c5cedd52ea1157b70ac815",
            "e5d4f631df02d08546dae6b05acc3fe1",
            GCM::new(vec![0xb3, 0x54, 0xa2])
        );
        test_encrypt_aead::<AESKey128, GCM>(
            "37a745697cc56b42aa9010885aaccc81",
            "0e14ca71b76f201fb05d7ef83506e1d0d4c2f56461b2eb3e9f4271260f481d8c80e70e7fd07296ed32eb9bb88ccb57151f64edc0f02ac1f2e68e10cdaf12f2db",
            Some("9ec77c3dcad10dc72817f14901b3ed12a4ab2246301c4ae4c2345df49296017c"),
            "621511a2a62ec78309852bcf3ca04529b0f6a25eaf16124b914839ece5b05e571466a97ac5d51595528daf0b709a1c2943bc41915fcd3ff033efce96c518418f",
            "eedf6f82d61b019f11eb4059348e52bc",
            GCM::new(vec![0xc1, 0x23, 0xfb, 0x89, 0x7c, 0xdb, 0x94, 0xb5, 0x88, 0xda, 0xb4, 0x56, 0x1f, 0x61, 0x62])
        );
        test_encrypt_aead::<AESKey128, GCM>(
            "1b8c4f925e031e8b674a938c4ff363bd",
            "7a64a902867efd92290ab8c52654e2aaa6d4979afd35755963534e12660dff23bf5432595c2acdcc7d704b56256a453b5624ec19acd4e55de2765f7da7f9b604",
            None,
            "da1f525566eabc9c6f55b98bf5d758afb37ab8d48d99424987f458d9ab1201d8ee4f8dceb45e608277068a9578d7d01f0c217687481d9df369de508a65d1671e",
            "c6c9e90d8781c75c382578493d72bde7",
            GCM::new(vec![0xdb, 0xc1, 0xe9, 0x41, 0xc6, 0x06])
        );
    }

    #[test]
    fn gcm_encrypt_192() {
        test_encrypt_aead::<AESKey192, GCM>(
            "16b6312de67c4bf4a21c2493a96f1819f1755b85f8cd38ea",
            "4b4f2a5c86ecfc0e71d5293f4c717f42c88119553bff72361b44218c8d6eba19a044cd1fa35e4cf5ce77f1c6085cf1a809411bf4ad7b1a4049a5f1f1ceb75789d59f18cd34",
            Some("12321c28bb4614f183695f6611efb1c32e48125a15f3bb05e8809a5602c3a315"),
            "0aa4b2c329d283a66ba89eb0d209e3d0678026dc94c893ea9c78c16be15db0293806b61ce29d41e1166ec89683fafc2d5e1d1902b99661063f34d55f5af6de8640656bb506",
            "1d83a4390cbe8736137601bacbc0ac13",
            GCM::new(vec![0xef, 0x43, 0x03, 0x02, 0xcb, 0x6c, 0xd4, 0x9d, 0x43, 0xa4, 0x73, 0x37, 0xff])
        );
        test_encrypt_aead::<AESKey192, GCM>(
            "6bba31e358b78829fa661e40b1f3a8fd154bfb588941170f",
            "ae6a312905461c7b734e6e874afa3db73bead0b0aab8e6bb64dbb3ff27605e50ccccae6f5dd304756c8b52",
            None,
            "3525d57ac3948165d0983f897b31bdb5551a66895dd1ef210cb3faa1b7200f418fe9664a3f5fd0f8ef08fb",
            "00df4394b496466a4a24cefb0ebf1e5e",
            GCM::new(vec![0xfc, 0xe1, 0x78])
        );
        test_encrypt_aead::<AESKey192, GCM>(
            "4c59e5c6f2103cbe81cc92cb695b3411193100952ea694a6",
            "c74be3f7e5023167dbfab93c02f21834192e57253cef25868d5f6392a2cee21fb928419f81f3c13e24d998949791db5579ce83fd2fe33b9f0fd7a3999d71b8bf",
            Some("d58e506fc6066732b664307ac083fb6c32e8ddd4b3699e9b67b0573d68510dd5"),
            "a0726bb141ae2d51cba693a7c999f69f19c0c053789a493a0080535acf8a4b23820ad5e096d8eb01b6d9cc3c3d4f4b136c678d9b910471c60bbe1e0a873db273",
            "aae18b4f230a3a2e9b67b1d41ff3b2cf",
            GCM::new(vec![0xfb, 0xb2, 0x34, 0x84, 0x4b, 0xb2, 0x0d, 0x33, 0xe0])
        );
    }

    #[test]
    fn gcm_encrypt_256() {
        test_encrypt_aead::<AESKey256, GCM>(
            "1760743176215e1bef972185286b108b6675cb86f0f3f04d8a5148b3aa9ae28b",
            "a6c989965b9fcadaba7c02440bf0f830a6d249d555de87f9a3ee6947f6917e",
            Some("ddb36206ab2bb82d9ae69f54115e6fdf"),
            "e346b645fd707c6e14f48957b40999d5363459598e8ba694857dddc6219c19",
            "068385850aa5617c052d9d469d1365c3",
            GCM::new(vec![0xf4, 0x06, 0xf9, 0x13, 0x68, 0x63, 0x92, 0x1b]),
        );
        test_encrypt_aead::<AESKey256, GCM>(
            "c1b3ad6133759aa52799748c267e4859158f047c09428d11ad849a07a943c3d8",
            "5f19ef55354d6747dfb4bdcc7bdb79421240",
            Some("c443f1fc7d2e9ee065b40ef820d26c4ec400ec6aa3d36fc36b90c87d84c1ee8f"),
            "7f0fa0af2fcfb44cdb89e6f5862205e19177",
            "aa209759c42c69152c59af0362e185f2",
            GCM::new(vec![0xb7, 0x95, 0x5b, 0xcc, 0x05]),
        );
        test_encrypt_aead::<AESKey256, GCM>(
            "0dd7fe5b767e89cd6aab6546d728a438817ef2ae49697e580a244faf78ce3f4d",
            "e90bd607facb161411b8adef368d72fcd9a6fa205b056d106c9c53a6a6300f864bdd8668d848beb73a71412dd4a0cb7b08ba46f59b9fba4c4b7744318c60a5b7",
            Some("aa3b7e5d2e6af3378d5a379b71c27225"),
            "e19f4603eeebc3fb5490a4f141bd74a59be8dceff9d10ca374cb164db9f776d8d85c8e8b0d206339eed64f44d0a5917917e29627aed9886bfa9a5f0952bc67a7",
            "186e07dce85fc2b10a049d3a2146e755",
            GCM::new(vec![0xc1, 0x0a, 0x69])
        );
    }

    #[test]
    fn gcm_decrypt_128() {
        test_decrypt_aead::<AESKey128, GCM>(
            "3bc1aba2e0282e0287ab160e4ea2d531",
            "044b96fda4a524240ff2a8e774a74afa8e4379c03711283a3c94a2be8889bc5a049d71a9f206e26aa43848f059f50bae6009607ea6e85387343ff167e329e89a",
            Some("263a7ee88d3252727a5381658106f8c1"),
            Ok("33eaa080f2d9b2407656c4793c672abccd5372e058a700a4703a94aa2e47d246d4d0186b20d293d393d0708016dc73cc5af43f3244d5e19364f0c8b8022ddaef"),
            "00b55151e1e7817f5cea60f81cf6bf85",
            GCM::new(vec![0xc0, 0x71, 0xd4, 0x94, 0x03, 0xa8, 0xd6])
        );
        test_decrypt_aead::<AESKey128, GCM>(
            "284e24136e8516cdbab418b4a8fa4585",
            "f89772489d524f93",
            Some("47c1e154ec9a97c78db6fa365c726411"),
            Ok("1be436bbcfdd6a50"),
            "fa05e5c7c97cf21764a9a6816b9a8a0e",
            GCM::new(vec![
                0x85, 0x07, 0x15, 0x75, 0x77, 0x82, 0xce, 0xc6, 0x45, 0x29,
            ]),
        );
        test_decrypt_aead::<AESKey128, GCM>(
            "e602b2ec4bf3a29d96504bbd57533eac",
            "83e9b26272fe2d77eab1338152ba3541845e87357bb62158a99e5c288f45d550a5cba2780a2e41051fc2243ccac6b85213540c9cb72ef8341272867bd17e8618",
            Some("d8c3a7fdb21750b9546a71a5111793a805bea531c51a701f110f02ec24c34338"),
            Ok("679b9b82db5168cecd44b814842dfea6be3b9070ca5d590ce3d9aed96fc29860ea5cdd2c8936ed2c1a8c8e5a1ac219f309e086f8faf1e3b5cca8bb055d60be86"),
            "77b78945720359aae97b18444708ca51",
            GCM::new(vec![0xa1, 0xfa, 0x20, 0x66, 0xb1, 0xf0, 0x1c, 0x8c, 0x87, 0x8f, 0xbc, 0xb7, 0xa1])
        );
    }

    #[test]
    fn gcm_decrypt_192() {
        test_decrypt_aead::<AESKey192, GCM>(
            "d9bc43647e2078ad47d19146e6393f26f60a1b4e7165f64d",
            "82d0a5f94761830204ef4dabf17986305ea75c48b6acfbcc0091c16aebf115c4aba0febc871ec891dcff547424848e95a7adccd7eae5a24f3fc27419a90e14af",
            Some("10d63e49a5e1c8e28566005f02ada9f02ffd069665530bb4756bf0d46b4d6f4b"),
            Ok("d904a3e09eebfdb52f36bdc9433049bd9af2210571527383d37fcc15374a5721ccd68cd7a7c8104e01979159d014a474fbce3009bf1eee14ebe5c3fd422bb610"),
            "92aadfb2c9c72ee5b4ec8b77a45fec25",
            GCM::new(vec![0xa4, 0xdd, 0x43, 0xe3, 0x18, 0x0c, 0x02, 0x2c, 0xeb, 0xbc, 0x6f, 0xd8, 0xfe])
        );
        test_decrypt_aead::<AESKey192, GCM>(
            "82f0458d7cddee1a42c89a99d00647e2a8b3637a0a2d082b",
            "40dc7721b0adb3b0f657ae9bab6f96ffbf3d869e5da33cd9dc805a469c8fbd78281237083e95e01e3cb9a5fb8f3c831e494c31e0a00731a0c2175ff4df1fe0b7",
            None,
            Ok("a86ba66fd5f16b85889b3b295fc9ff48f49bf0049ccbde42da3d17a900c6dc6410906c74a64771b6966d49a72bbe69e12061682a223e0617453a33172e82c730"),
            "4fe2369caec9188e111507a4e9f0ca29",
            GCM::new(vec![0x06, 0xfd, 0x2f, 0x97])
        );
        test_decrypt_aead::<AESKey192, GCM>(
            "7189bb7c3cc7b1d6983e807f59ed1227b68d80a7ad42ea98",
            "8a82fa60174175236bb07a18432b96f60cb0ec286b683a5a1db6db1c012bca32ccd06b1ab15cb258d209787c53a50c98943e51d4817be52493d59e2cbd98153e",
            Some("33b028714470a8bde43233b2857341d2301002b2214f009acefe758afa9280a89719a36cd962d9cc7f285f5a33897f96"),
            Ok("41d47c4cc8b4e119b0686cc76da471cd8bc54568e2544398cbe855b3ad61b11b69a5d6a77c0913bdc7ad45b37f37d7cc2795b6ea90601b7a4651896dfb58ff1c"),
            "f03016e3699a9138828cc7d8af36ff14",
            GCM::new(vec![0x4f, 0x48, 0x42, 0x8e, 0x30, 0x34, 0xeb, 0xa2, 0x6a])
        );
    }

    #[test]
    fn gcm_decrypt_256() {
        test_decrypt_aead::<AESKey256, GCM>(
            "15c77fad3a965740eb7e2b74a4a403f62d71be55d0aa442b6fd68c25451e207b",
            "680e50ea0d89e5a0b132cbf7853860afaabdedf2949220a56ab0f7f82f9f3206c6ac66ae907d",
            Some("522486ef04045c557fb70215add01c323ee23f22a4ca047621d8f13ea6763525906046311b18d518d44c3c29fbca4c5f"),
            Ok("546f34d4e13e6cd859e023b434d090d343856d9807ba7ec8dd675eaf74ae79eb25d190f10d7c"),
            "b1a8e8ae33ebed6fb8781617e1cc3ebb",
            GCM::new(vec![0x0f, 0xda, 0x9b, 0x53, 0x45, 0x5c, 0x5f, 0xfb])
        );
        test_decrypt_aead::<AESKey256, GCM>(
            "1bf9c9fd91e243498ce2020dc86187062b59ee972596ef3d4f1873987f5cc47c",
            "35c34af929b6306b0215c1d6b149cc154426d703fbdb7e92a2198dc1a0a6dc05c7bdf88e6f9bb2d033d1b7a795047d00a667a299e805d39e32607ded708d4238",
            Some("af62897b0cef284d495ccb8f169262d7"),
            Ok("83640a7badce216a550ae7aba2cacd86b5c6863f4b909a64aedd22deff7e9a98e771cf8e8c78d02b6b473dc60fb0a204dc55596f396435f93a3c56ebb1426640"),
            "d75ea2365d2223c13d7af0700ec7d81c",
            GCM::new(vec![0xea])
        );
        test_decrypt_aead::<AESKey256, GCM>(
            "57517971375db3799c714aec531ff48a39ca9aba795ae376e07c07692cc73ae6",
            "2aa3bdbfe753f7c85b372bb3772412ea24a2884623f95fef7c39bde2a7f7522e689f27f694c28f63de3a8f7e81fb901498931a1b5f0735218dd5b5fa7a155ee2",
            None,
            Ok("737ff04a7472c020c858c382cf0c73ff6af2b67333eaf17e5b143cf45b9112a12a99b84f0b5a48604fe3c99fd852bcb0fb8d53be18fb0f70468791e4ff3d0b27"),
            "a5f464bf0534ae8bfcc22ea3ad4245ee",
            GCM::new(vec![0xfc, 0x0c, 0x99, 0xac, 0x99, 0x2d, 0xd0, 0x62, 0xfc, 0xc7, 0xcd, 0xec, 0xa8])
        );
    }

    #[test]
    fn gcm_tag_mismatch() {
        test_decrypt_aead::<AESKey128, GCM>(
            "78ab61e03443199e9dce64d7b5a28cc6",
            "a0ada4f1a871235b299ecb49e7d7bf3ec9d2398689a39899a7b503f363262ad0b8f030e0a60593aa5cfb16ab3b07610b2666d10073276ea5bb5daba0e1755cfcb3025cd597dd44c8ba503b8ee6882bb58842409a10f22d0ccc2cac9fb0bb402614923732f4d6ed6445d6c8ea484f53cbc88fae05f2cd8f98b5e552fa024aea64",
            Some("a37634e0b591f10e25d04db1c0541263"),
            Err(AeadDecryptionTagMismatch),
            "132414aa0f3dc80a845e00b58a2caf4f",  // last `f` should really be an `e`
            GCM::new(vec![0x05, 0x23, 0xef, 0x11, 0x85, 0x90, 0x32, 0xb4, 0x0a, 0xdf, 0x56, 0x04, 0x93, 0x76, 0x74, 0xd3])
        );

        test_decrypt_aead::<AESKey192, GCM>(
            "10e1ff7ddcfabf41be08bfdbf3b14db54f9603649f43afe8",
            "6f815b9fd97dfc8cd69d788fffc55615d4eb3da3dd05ae775d1a37a753a445417a384189ef6f3eb8b7ec594c0964c687b1c3da1b07ee9d6810b10af2160c1870f4053ed10cf8597fbc29ff79a0566f0b78c662a2b3709558330f23bfdc3a47f228effa8c9ec8ba442c9f5361bf5b9ccf2e8ad4dd5d394f35666d26b01797a87d",
            Some("feda55f9d6f0f7e3591da15728a54c6cad6f24856049fd4457cebd82d5cb22eb00da44aea499a91e9377c14ae731af66"),
            Err(AeadDecryptionTagMismatch),
            "a00b475d7f0d371e6b3aaa9fd678b21d", // first `a` should be a `4`
            GCM::new(vec![0x97, 0x2e, 0x1c, 0xc4])
        );

        test_decrypt_aead::<AESKey256, GCM>(
            "f2601f8992b98cf6f0c949649faa86afb4699cd5ea0c1e4deb324ce76af00a91",
            "173fd193c2a5067c6693098bafce0225c9f099765df681bd22fd3c20e62f4d88794645f5a6566710dfb5699162aafea1ba157eda8d005b1261cc33fe8d995aa4d7776c221c074c9919967b37c201d53a4cbf4e2489b9d075afab9e1e49b93b83036f87a64fe2b81c4da150d363e16ab08481783b378c081eac2da6f9bd69a920",
            None,
            Err(AeadDecryptionTagMismatch),
            "42513dc22efb76c633e16c358f63303e", // The `7` in the middle should be an `8`
            GCM::new(vec![0xb3, 0x16, 0x61, 0xcc, 0x47, 0xbe])
        );
    }
}
