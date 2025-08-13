use crate::cryptography::aes::galois_mul::gmul128;
use crate::cryptography::aes::{aes_encrypt, AESKey};
use crate::cryptography::mode_of_operation::{
    AeadDecryptionTagMissmatch, AeadModeOfOperation, ModeOfOperation,
};
use crate::cryptography::mode_of_operation::ctr::CTR;

/// The Galois/Counter Mode (GCM) is a mode of operations for symmetric-key block ciphers. It not
/// encrypts data but also authenticates it with optional additional authenticated data (AAD).
pub struct GCM {
    /// The nonce is a value used exactly once. It will be appended with the counter to create
    /// a unique 128-bit number for each plaintext block (independent of block values). This
    /// is safe as long as the `(nonce, counter)` pair is never used again. It can be of any
    /// length (even more than 16 bytes or fewer).
    nonce: Vec<u8>
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
    /// `m = len(A)`, the amount of 128-bit blocks in `A`<br>
    /// `n = len(C)`, the amount of 128-bit blocks in `C`<br>
    fn g_hash(h: u128, a: &[u128], c: &[u128]) -> u128 {
        let m = a.len();
        let n = c.len();

        // This is where the padded information is stored.
        // The 128 block that is stored here is len(A) || len(C) of the 64-bit representations
        // of the bit length of A and C. Since m and n are the amount of 128-bit blocks, we need
        // to multiply this number by 128 or shift to the left by 7, which is where the shifts come
        // from (71 = 64 + 7). If `a` and `c` weren't whole 128-bit blocks, this would have to be
        // changed.
        let last_block_value = ((m as u128) << 71) | ((n as u128) << 7);

        let mut hash = Self::g_hash_with_initial(h, a, 0);
        hash = Self::g_hash_with_initial(h, c, hash);
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
}

impl ModeOfOperation for GCM {}

impl AeadModeOfOperation for GCM {
    fn encrypt<K: AESKey>(
        &self,
        key: &K,
        plaintext: &[u128],
        aad: Option<&[u128]>,
    ) -> (Vec<u128>, u128) {
        let zeros: u128 = 0x0;
        // key dependant point H = E(0^128)
        let h = aes_encrypt(zeros, key);

        let counter0 = self.calculate_counter0(h);

        let masking_key = aes_encrypt(counter0, key);

        let ciphertext = CTR::encrypt_with_initial(key, plaintext, counter0 + 1);

        let mut tag = Self::g_hash(h, aad.unwrap_or(&[]), ciphertext.as_slice());
        tag ^= masking_key;

        (ciphertext, tag)
    }

    fn decrypt<K: AESKey>(
        &self,
        key: &K,
        ciphertext: &[u128],
        aad: Option<&[u128]>,
        tag: u128,
    ) -> Result<Vec<u128>, AeadDecryptionTagMissmatch> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptography::aes::{AESKey128, AESKey192, AESKey256};
    use crate::cryptography::mode_of_operation::gcm::GCM;
    use crate::cryptography::mode_of_operation::tests::test_encrypt_aead;

    #[test]
    fn gcm_encrypt_128() {
        test_encrypt_aead::<AESKey128, GCM>(
            "af0918cd2a119a5853ebeadfc9cbdd8c",
            "6a76d46d9170d484528f8ccf702469fe64106a49253224fd4f36b1eba9efc1edb980d1351a1963e39fba1043dfccb99b5fe30a10183707253fe53e4626e67aa0cd14b354a243ee88846a084115bc1f4e65e9a6dbed4527ab7da1a5a1783147882feecfa1e26637a745697cc56b42aa9010885aaccc8192610e14ca71b76f201f",
            Some("9f4271260f481d8c80e70e7fd07296ed"),
            "506fe244640dc5e2eb0a140867381fdd23cdc3f2c24d92f6ff4e49dcdf099eebe5c1277396e797be9e6f2455acf6f44a9728028bd9ff5b8a2ee4a56db40168f0bab2b7dabfeeba979958a02ba745caf29d1394289fa0a29cec3468b91dda573dc41ebc4687245b7ca3d3c63531e875ae01dbfd854dd3de52c357dc95365a041c",
            "0fe3a44da7eae9798d24197259800757",
            GCM::new(vec![0x7e, 0xf8, 0x35, 0x06, 0xe1, 0xd0, 0xd4, 0xc2, 0xf5, 0x64, 0x61, 0xb2])
        );
        test_encrypt_aead::<AESKey128, GCM>(
            "32eb9bb88ccb57151f64edc0f02ac1f2",
            "e68e10cdaf12f2dbb2b5c177c123fb897cdb94b588dab4561f616280409ec77c3dcad10dc72817f14901b3ed12a4ab2246301c4ae4c2345df49296017c1b8c4f925e031e8b674a938c4ff363bd437a64a902867efd92290ab8c52654e2aaa6d4979afd35755963534e12660dff23bf5432595c2acdcc7d704b56256a453b5624",
            Some("5f7da7f9b6042bdbc1e941c6061916b6312de67c4bf4a21c2493a96f1819f1755b85f8cd38ea3b814b4f2a5c86ecfc0e"),
            "f8a8228331e3eab4586440387cdbfbc0323641776e7dd2747863c555e404c0af879696ce4bee33ba7a5305e0428505052256a3f68f6a5b64e8680213e158e9ab9f1ec7fa220c000c025b8b705a67d79d265bd9ca65a51ef05ae1203ec16b0c620cd38c17ccb6079709a46ca809cfa4a4d9df19d43c5f858afa53993645dc0443",
            "440f952e4bac13d8eefa6ccf8bb0e6fa",
            GCM::new(vec![0xac, 0xd4, 0xe5, 0x5d])
        );
        test_encrypt_aead::<AESKey128, GCM>(
            "71d5293f4c717f42c88119553bff7236",
            "1b44218c8d6eba19a044cd1fa35e4cf5ce77f1c6085cf1a809411bf4ad7b1a4049a5f1f1ceb75789d59f18cd34f1e860ef430302cb6cd49d43a47337ff4212321c28bb4614f183695f6611efb1c32e48125a15f3bb05e8809a5602c3a3156bba31e358b78829fa661e40b1f3a8fd154bfb588941170faca33a4dae6a31290546",
            Some("fa3db73bead0b0aab8e6bb64dbb3ff27605e50ccccae6f5dd304756c8b5212fc"),
            "e301a1f814dedd87aac3050abc3c9b9a5bf26418e65794705b8190e7195189d0e89bca6702f5fe2166d239a997410f3fd5df6ca5925f7dddc1015c496b3b306ee3e3aea68b5cf0aee1322846bfd65da2699c4e6c3f7e174e306a9a9ba357d6904e174c3624198421c42add1c33554b6eb1b2f7483cb1852b06d6ee07b1863b14",
            "3816e5939593ce40026c7bc4c91cfc15",
            GCM::new(vec![0x7b, 0x73, 0x4e, 0x6e])
        );
    }

    #[test]
    fn gcm_encrypt_192() {
        test_encrypt_aead::<AESKey192, GCM>(
            "e178f3084c59e5c6f2103cbe81cc92cb695b341119310095",
            "2ea694a68d50c74be3f7e5023167dbfab93c02f21834192e57253cef25868d5f6392a2cee21fb928419f81f3c13e24d998949791db5579ce83fd2fe33b9f0fd7a3999d71b8bfd745fbb234844bb20d33e053d58e506fc6066732b664307ac083fb6c32e8ddd4b3699e9b67b0573d68510dd51760743176215e1bef972185286b",
            Some("8a5148b3aa9ae28bb7a13c34a6c989965b9fcadaba7c02440bf0f830a6d249d5"),
            "d7eeb360e8814970226d6d186a5492b5464d41fb288816f29d9381eb10c660aee7e089fd79f324c80a3beb94ac167d559dd403c9e6cfa2b5b984bd12b5f01d40bc076c09a8b859e821cd7afff23deae8aef02f7f62027b9ab0b6e76caffb34cb7deb0fa0680efb010e8ee177c0d0c87596785f9435367e221443bd99b8ceec1b",
            "0364d6cb5601e7f29f6941961bee445c",
            GCM::new(vec![0x8b, 0x66, 0x75])
        );
        test_encrypt_aead::<AESKey192, GCM>(
            "55de87f9a3ee6947f6917e8ec83bf406f9136863921bed35",
            "ddb36206ab2bb82d9ae69f54115e6fdfc1b3ad6133759aa52799748c267e4859158f047c09428d11ad849a07a943c3d8361b5f19ef55354d6747dfb4bdcc7bdb79421240e821b7955bcc05b54ac443f1fc7d2e9ee065b40ef820d26c4ec400ec6aa3d36fc36b90c87d84c1ee8f0dd7fe5b767e89cd6aab6546d728a438817ef2",
            Some("824be90bd607facb161411b8adef368d72fcd9a6fa205b056d106c9c53a6a630"),
            "ab5b36eb9be7cb24be4413624d3d2172ec42b774ffd0973f91d3a83454f27820ac0bde38c77f3ebfd1defdc3f840ce34cc75354257bd87976c7d35986d6264a6611d4dfb544cda295ea4f6261b92813b5dcec918d26ea91a0fd6720750ccea47cdfee86b170139930df41aa99e182a8841ef86c4355429c23856ae54bb1cdc8a",
            "38ec49e924a725dffedae50d1be45fae",
            GCM::new(vec![0x69, 0x7e, 0x58, 0x0a, 0x24, 0x4f, 0xaf, 0x78, 0xce, 0x3f])
        );
        test_encrypt_aead::<AESKey192, GCM>(
            "0f864bdd8668d848beb73a71412dd4a0cb7b08ba46f59b9f",
            "ba4c4b7744318c60a5b7fbcd8812c10a6935aa3b7e5d2e6af3378d5a379b71c272253bc1aba2e0282e0287ab160e4ea2d5317f33eaa080f2d9b2407656c4793c672abccd5372e058a700a4703a94aa2e47d246d4d0186b20d293d393d0708016dc73cc5af43f3244d5e19364f0c8b8022ddaef37c071d49403a8d62d263a7ee8",
            None,
            "fd7afdb88fe47b2bed5f473a734b842c981a0bae6e2ff6500dbcd78a4cdef23e55dddaa11b24139605604b162d610d88a78d2548deea8716183c49ca3105f452a29aa6f3950e039c44d7a5de9dc461c0a77e007fb7bd4b74844024459ef46cbd0d7c99b76ea71247bb2121c33971fea9ce25186485243dec046fbf5863e9a5f7",
            "06ee14a11045933af77c14622e441d9c",
            GCM::new(vec![0x52, 0x72, 0x7a, 0x53, 0x81, 0x65, 0x81])
        );
    }

    #[test]
    fn gcm_encrypt_256() {
        test_encrypt_aead::<AESKey256, GCM>(
            "f8c1284e24136e8516cdbab418b4a8fa458530071be436bbcfdd6a50c24e8507",
            "15757782cec64529b489813247c1e154ec9a97c78db6fa365c726411e602b2ec4bf3a29d96504bbd57533eace047679b9b82db5168cecd44b814842dfea6be3b9070ca5d590ce3d9aed96fc29860ea5cdd2c8936ed2c1a8c8e5a1ac219f309e086f8faf1e3b5cca8bb055d60be86c960a1fa2066b1f01c8c878fbcb7a1fb93b6",
            Some("71a5111793a805bea531c51a701f110f02ec24c34338d9bc43647e2078ad47d19146e6393f26f60a1b4e7165f64d53d9"),
            "723f8ed9ba964661ec0f804cbca56fff025a7cd332166cf420e85480f04227965aedea3b4653b5029045f08ca5cf5ccf90a5a80a15afc307ef30a27820dc17aa87afc47de8ba12eaa73ea4f5ada220cea939fd2dd06cd399e730b9c9e35b33b866f89eb85f978dce495c1311018ab5e0b975b5ed279aacd5f12eb9891b5005d2",
            "883005160a3a45e40e0343d742d0e99a",
            GCM::new(vec![0xd8, 0xc3, 0xa7, 0xfd, 0xb2, 0x17, 0x50, 0xb9, 0x54])
        );
        test_encrypt_aead::<AESKey256, GCM>(
            "04a3e09eebfdb52f36bdc9433049bd9af2210571527383d37fcc15374a5721cc",
            "d68cd7a7c8104e01979159d014a474fbce3009bf1eee14ebe5c3fd422bb610f164a4dd43e3180c022cebbc6fd8fe4610d63e49a5e1c8e28566005f02ada9f02ffd069665530bb4756bf0d46b4d6f4b82f0458d7cddee1a42c89a99d00647e2a8b3637a0a2d082b61a86ba66fd5f16b85889b3b295fc9ff48f49bf0049ccbde42",
            Some("74a64771b6966d49a72bbe69e12061682a223e0617453a33172e82c7301c06fd2f97187189bb7c3cc7b1d6983e807f59"),
            "16a0bb775f3f99ccd6e3f96c88b465fa2fe1f326c112c090841203d12e1574615a2449f4a211cc8bc438b73f8456f9a67d07bee3a1f1b9bf74e60e8440c8c94c70a0b4c5b4e6f32493ec79b80c1bad8a17dfaa120e1f9902648bef2576893012f4a890c761ca22ce4f3973197f3cad5608f9013d2e687a74fe7c290542b1163d",
            "d0bae226aaf74cbc8065155bedc7a899",
            GCM::new(vec![0x17, 0xa9, 0x00, 0xc6, 0xdc, 0x64, 0x10, 0x90])
        );
        test_encrypt_aead::<AESKey256, GCM>(
            "ed1227b68d80a7ad42ea98904a41d47c4cc8b4e119b0686cc76da471cd8bc545",
            "68e2544398cbe855b3ad61b11b69a5d6a77c0913bdc7ad45b37f37d7cc2795b6ea90601b7a4651896dfb58ff1cbea687424f48428e3034eba26a7c33b028714470a8bde43233b2857341d2301002b2214f009acefe758afa9280a89719a36cd962d9cc7f285f5a33897f9615c77fad3a965740eb7e2b74a4a403f62d71be55d0",
            Some("42546f34d4e13e6cd859e023b434d090"),
            "65c94a281220735529c03941a4a6822004a42befa51f1cdf453ff1851535af463bc410bd0fd1baf8f09dc4ce6fae9154cddcc466bc6df3e1f660f18784847192fcc41dcb66e1df97df9451dede2ebe9d3aba7175ab8a9b189d965fd0138cf76834117ec5c5de6986c1c74dcb533b3343ed9e6cdb4bbc265dce743604333248ee",
            "bdcc44e73efaa146bc8df1fbf33c9d4f",
            GCM::new(vec![0x2b, 0x6f, 0xd6, 0x8c, 0x25, 0x45, 0x1e, 0x20, 0x7b])
        );
    }
}
