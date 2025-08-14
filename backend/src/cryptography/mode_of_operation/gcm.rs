use crate::cryptography::aes::galois_mul::gmul128;
use crate::cryptography::aes::{aes_encrypt, AESKey};
use crate::cryptography::mode_of_operation::ctr::CTR;
use crate::cryptography::mode_of_operation::{
    AeadDecryptionTagMissmatch, AeadModeOfOperation, ModeOfOperation,
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
        // key dependant point H = E(0^128)
        let h = aes_encrypt(0, key);
        let counter0 = self.calculate_counter0(h);
        let masking_key = aes_encrypt(counter0, key);

        let calculated_tag = Self::g_hash(h, aad.unwrap_or(&[]), ciphertext) ^ masking_key;

        if tag != calculated_tag {
            return Err(AeadDecryptionTagMissmatch);
        }

        // encryption and decryption are the same
        let plaintext = CTR::encrypt_with_initial(key, ciphertext, counter0 + 1);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptography::aes::{AESKey128, AESKey192, AESKey256};
    use crate::cryptography::mode_of_operation::gcm::GCM;
    use crate::cryptography::mode_of_operation::tests::{test_decrypt_aead, test_encrypt_aead};
    use crate::cryptography::mode_of_operation::AeadDecryptionTagMissmatch;

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

    #[test]
    fn gcm_decrypt_128() {
        test_decrypt_aead::<AESKey128, GCM>(
            "d343856d9807ba7ec8dd675eaf74ae79",
            "9f9e849ccadf0030b85c7cbb831f59234bc9539e7882af407c6f0c0551261a9873c0c3bebe1a1c43fb725012e0d8e066217cb396b214f9dc960ca4231ce763e42e31ee05b65bb0e12f2276ab7fa2333cf16f456578c03cb2a1323c787e5d11ec38afedaf0c9cfcb55d251b4d29758aa3b05dfc4e2771e4dd20d54549b67341d9",
            Some("cf8e8c78d02b6b473dc60fb0a204dc55596f396435f93a3c56ebb1426640c906eaa92aaf62897b0cef284d495ccb8f16"),
            Ok("eb25d190f10d7cbb3c0fda9b53455c5ffbfbd375522486ef04045c557fb70215add01c323ee23f22a4ca047621d8f13ea6763525906046311b18d518d44c3c29fbca4c5f1bf9c9fd91e243498ce2020dc86187062b59ee972596ef3d4f1873987f5cc47cbe8f876383640a7badce216a550ae7aba2cacd86b5c6863f4b909a64"),
            "a3dbd8d9aeaeb0f331937557ccf754b8",
            GCM::new(vec![0xde, 0xff, 0x7e, 0x9a, 0x98])
        );
        test_decrypt_aead::<AESKey128, GCM>(
            "9262d757517971375db3799c714aec53",
            "ce8d7e4d5338986a2c81ef1cd89e954c445c95bb7974047937a1555839cbf4da1597bb15215a3223deefd8ce10c5e4814a1dc7b956d9fc832630fc29cd0bf08b2b3e6e9914a225989aee46a695a97f68641968f14b14973d4349a7c981a2cef822b53ff85377fa2ec43f7319225e56327e176d41342391839a856d3830d9631d",
            Some("50f7fa895795bc2a985e653968ece4b0"),
            Ok("1ff48a39ca9aba795ae376e07c07692cc73ae67d737ff04a7472c020c858c382cf0c73ff6af2b67333eaf17e5b143cf45b9112a12a99b84f0b5a48604fe3c99fd852bcb0fb8d53be18fb0f70468791e4ff3d0b2764fc0c99ac992dd062fcc7cdeca895183b4e1e31a71fdd7c72c8f9158a53e4c4ca5b35e44ce227224186d794"),
            "dd8eebd74633f0016076c0e4b2229e73",
            GCM::new(vec![0xab, 0x96, 0xe9, 0x48, 0x04, 0xc5, 0x31, 0xae, 0xd4, 0x90, 0xc4, 0x76, 0x28, 0x73])
        );
        test_decrypt_aead::<AESKey128, GCM>(
            "b990f6d0ffe088129512cfef0cf0db8f",
            "cfe3af89b1ed59e08dab1683e9ac322f5e669721b21944f0c93def4ea272ce1f9bd614bb73e2d204a09a7fe29b2c4a608d434db69e434c15a290d2ba035fb3880acadb6e5616d1b479f140228a71e390b649f25147998f992a95f69f1878afcca58d933c2d668aa23a940b2fbed1ae696ff498edcac031f7a614aab7bb34460d",
            None,
            Ok("35b26f9f8183bc910f5974d6acd8c369e5b811ad977f279f4db53f3913980eddf0f27cf74219e98df4902cb2668c5238742e76feea3ed36c5ab1af00d817a3fb0b2d35cafe2d236a3e8c7b2f300effddb0e74aab7fc80f34af057a2914e0c0e3feedc8f36f6237f932d4bdb4b468a83c5494c6993eac326ceed0a7e5a9679c1a"),
            "dd27913a225c3cd2a1e6895de907f3cd",
            GCM::new(vec![0xd3, 0xe5, 0x9b, 0x30, 0xe2, 0x3b, 0xf4, 0x27, 0x0f, 0xd4])
        );
    }

    #[test]
    fn gcm_decrypt_192() {
        test_decrypt_aead::<AESKey192, GCM>(
            "b117ca483924cfbcbe086375c2184a8f6f39dc76ef83f081",
            "3923326c58db314bfb54fee4e77562e04d4218ddae49b49eb9f87a8e002df23fb40f96dac3a4c5cecf7706b2da31c7b1844802cce705285ec2869b0441bbd0938540a36fded010431be816549d87397967120b3a6ffe004b1ee37cb4e82197b11bcb2aaa9a2caf34bea62217b6dac836a6761d7a9a137351055c31738cb67eca",
            Some("b599c3ae78af08ea41abd7b52c965013768d8e337cea5264ba4eb33502fb0335e6f6ff1101b908f730884ec043ac616b"),
            Ok("bdd74138d0525da6a2ad0ab6de4f0194e93fedb7539cc883f2d10ee9e493a818d2146a5e2363169c77f4dddf22224e41de9b103e4031e0533379ec539cf28c70a944dce7aa802b0ae4edcfc6caeddf5559d5fc195d01302678edfb3cac8f3fb4b4c382ab29a7bd5ef9f6686e47f452e70d02483fec0bc3b4624b1cd2068333cd"),
            "62049505b2801f104e1def8a553a771e",
            GCM::new(vec![0x12, 0x9c, 0xc9, 0x4a, 0x5a, 0xd9, 0x3e, 0xc9, 0xba, 0x3f, 0xe3])
        );
        test_decrypt_aead::<AESKey192, GCM>(
            "88c8f11845ac6095ece51830d83c2e5c4141591f2a5426e6",
            "75d0008ceabf66a354e8c5400418ba4fb291129ddfc2ffcecd0c9b614e31ee05473e953c294d3a61551d14e9a015845c572ac44e00663f79d71a1e8cc1c788c34a1ad96f4f5bf470debc9ff9ae26dbe11ecbd8c86e24e00c81007a5a01bd2d2417843f04f2922575b725f5443322121b67e1684651d49dc5783c2baf856f4a8e",
            Some("31c35ef8b325e736173782630d10b8f90a4380d44863b4b7279c6868201c830e"),
            Ok("9f333e925c5fe284dd8bcf16c364e1fa1b783b0d603a7f6b09bece8a638484a55f6154f1f066727ca88eb1a3c9660a864143ab4c2f5351dd7d6a4f91d551e27329701413fcfba07afcd951b49f425c2d18cbf7c2ec4f5625f5a388c725a385b46e978e86b0ff4df55f0334de2c1aa4e2f90b80d4c2d3ba7ba2957eea0eba1ff5"),
            "71543c73d4423adcbaafffb0d4ce2362",
            GCM::new(vec![0x55, 0x25, 0x03, 0xb8, 0xb9, 0x1f, 0x66, 0xe1, 0x03, 0xe2, 0xc6, 0x5b, 0x55, 0x4c, 0x3d, 0x4e])
        );
        test_decrypt_aead::<AESKey192, GCM>(
            "40577c42306c36f26a309ab2a0cae665f91978958ea723ab",
            "a87e73816cbaa97b649ed2f38a29011ef9dc688567170d0898fc2d0132be8ce81e943cf5e280a661dfbdd3648b270a2df68845b19ac3470ec90458970a4bb8b587ad45606d256c13a9d20c539dcc4bb105deec350e734eba75a962df7b437c97114417026fa23aba1f356d08cf311a45a231d3d6e87511613a57db35e11b4346",
            Some("b3049fde22efce4e499eda9222658367a9384cc2e678d6461144624abfd632fd"),
            Ok("c5105751b2a3be0c3b92dea9ea6b5ff27060cfb44e555a62db1196e7ecf2c50606b62b4e0dc03c605d2524b8b19d49ca3d7dee2b89aa3749f6407ea3e7d01ac7473c630117d0513feb250a4d33483b24745076d4b0962dafda1ebab0516ed70cf382cd1ab2a8dd0c51e12dc3914c683f515fdceaab4161e89e5195d5612c152c"),
            "5a43e961b6050b62a204dcbda6611f94",
            GCM::new(vec![0xef, 0xa0, 0x87, 0x64, 0x61, 0xfa, 0x9f, 0x6c, 0x11])
        );
    }

    #[test]
    fn gcm_decrypt_256() {
        test_decrypt_aead::<AESKey256, GCM>(
            "e412a1dee07e8ed97ceac3b815a8f40133801892f66eb161ec4c14d8c33a805d",
            "6ead46907959670059baee48a9570c92dfe024317f32d9eb8daf70f3206fa96ad4fcedd2cf7f04d2a07c972fb8abbba33dddfcf0d4abfbbf9bbb1cec8626982b063129251b9fa4735c1d6d53fcd25f9a4c5d7e95940e749c1519cd5f844e641e42adc2a68513eeb358c89d274e84ff364affc57ff058711662df3078770539db",
            Some("93055d01fbb7b9c15bfb68322cbbb20eca997c40a81180c9ae5dd820659ee5e5e13759e386ec63d279cc858825a2e25d"),
            Ok("b726f6a64938d756026c5058e79951378862dd160d65b3a531deca33491ef612af266e6d772b22f4638ad442361cc6f97d9e9c7017d0ea08b552a127a44e2001bd9336a04efdde95c40c5e5c1fcaace6034cd43cebbfa543fecd9a10007da7e140c958910e3dcb27a3f0866f22d7e8f29bfc5dd2c0f7b528da4759c44555ca7c"),
            "ba1d593885ee130527d651f3b364d47a",
            GCM::new(vec![0x0a, 0x61, 0xb0, 0x53, 0x1a, 0x2f, 0x59, 0x0c, 0xbc, 0x06])
        );
        test_decrypt_aead::<AESKey256, GCM>(
            "978c7610279c7836f9b1998befda76a310865282482d369c75c4ec8b688c4b41",
            "5357b6a78d886f766d844fc38f5664bc3c2c24e1bd050a6af2d1ddf72ee1d8ef5092f5f468794b5e7ba8bd446339f21ff6dfa7424b9794958410439f52db901db5a0d7831a37da5319ccb7078023dac05b6b03fcf9b9a1fc50532a4a31394857d13f49777ed285c521c459a8fe3227bbe0e3424edb974be1712393af153e62bb",
            Some("31bdec803c5a95df26eb1aa9fc5666e06a4feeac825cb3827a7961540b4cf7e9c6ca71d37cb93d5b3e071557fb9d2d76"),
            Ok("e794dc1020b9ef7c29fa5c0539768b42d2354698125858d20f76316f3870754e627491b2c00531f0cf04b19f38cf8cf523152f3939c19236ec46ff561f7ebc7bdcc11b811b2894e7c2aec1394e6336eac1d32435b17cb57378522a2be102053378b022ec1260897720fd935bbef7cd705ccd196b2a5c5d8e474895229a266095"),
            "46c546487530f86f7f236074f180fd6f",
            GCM::new(vec![0x90, 0x63, 0x9b, 0x2b])
        );
        test_decrypt_aead::<AESKey256, GCM>(
            "fc786aa0854197587a63a473859dd81c98838f3fff2f4edf23dcf8d782698019",
            "ab4ad5378e9474ced007d0676a04e72ebc2c922edef2dc82735b8e6a0e5ded8cbe881180e1f9296d4ad59688615e6bbeeb254166046dea91a98d5dfcabcbbbe2edd4101e4d0ec574135a23dee4d01309340dcb10a82815cf3ef5ba3a3887e60436afb70924094964175f2703fa84578ae1e3ba02c27695d9dfe377cb984a1204",
            Some("80bebcdbdfe0b32317aebe7016d0c83f"),
            Ok("17c841a2a8312afa677a8f64ece373a4aa5689d435515e841b966b9bd350fdd648a3a5d3ae6aa8057a7f36b32b3e59f77d203b293f6049a31856ba6ae78697078deac8fe767e428668d7b21791cf242c894993151c489252ceffbfe05a7df8f2863cb9b72981de83bf5c05d57a8d71856cdf72e8f706fcf9eb883c50bd7dba72"),
            "acdd681770c41d8057e163a71593cba0",
            GCM::new(vec![0x3a, 0xa5, 0x2c, 0xf7, 0x3c, 0x3a, 0x6f, 0x1c, 0xf6, 0x94, 0x27, 0x4e, 0x8e, 0x9a])
        );
    }

    #[test]
    fn gcm_tag_mismatch() {
        test_decrypt_aead::<AESKey128, GCM>(
            "78ab61e03443199e9dce64d7b5a28cc6",
            "a0ada4f1a871235b299ecb49e7d7bf3ec9d2398689a39899a7b503f363262ad0b8f030e0a60593aa5cfb16ab3b07610b2666d10073276ea5bb5daba0e1755cfcb3025cd597dd44c8ba503b8ee6882bb58842409a10f22d0ccc2cac9fb0bb402614923732f4d6ed6445d6c8ea484f53cbc88fae05f2cd8f98b5e552fa024aea64",
            Some("a37634e0b591f10e25d04db1c0541263"),
            Err(AeadDecryptionTagMissmatch),
            "132414aa0f3dc80a845e00b58a2caf4f",  // last `f` should really be an `e`
            GCM::new(vec![0x05, 0x23, 0xef, 0x11, 0x85, 0x90, 0x32, 0xb4, 0x0a, 0xdf, 0x56, 0x04, 0x93, 0x76, 0x74, 0xd3])
        );

        test_decrypt_aead::<AESKey192, GCM>(
            "10e1ff7ddcfabf41be08bfdbf3b14db54f9603649f43afe8",
            "6f815b9fd97dfc8cd69d788fffc55615d4eb3da3dd05ae775d1a37a753a445417a384189ef6f3eb8b7ec594c0964c687b1c3da1b07ee9d6810b10af2160c1870f4053ed10cf8597fbc29ff79a0566f0b78c662a2b3709558330f23bfdc3a47f228effa8c9ec8ba442c9f5361bf5b9ccf2e8ad4dd5d394f35666d26b01797a87d",
            Some("feda55f9d6f0f7e3591da15728a54c6cad6f24856049fd4457cebd82d5cb22eb00da44aea499a91e9377c14ae731af66"),
            Err(AeadDecryptionTagMissmatch),
            "a00b475d7f0d371e6b3aaa9fd678b21d", // first `a` should be a `4`
            GCM::new(vec![0x97, 0x2e, 0x1c, 0xc4])
        );

        test_decrypt_aead::<AESKey256, GCM>(
            "f2601f8992b98cf6f0c949649faa86afb4699cd5ea0c1e4deb324ce76af00a91",
            "173fd193c2a5067c6693098bafce0225c9f099765df681bd22fd3c20e62f4d88794645f5a6566710dfb5699162aafea1ba157eda8d005b1261cc33fe8d995aa4d7776c221c074c9919967b37c201d53a4cbf4e2489b9d075afab9e1e49b93b83036f87a64fe2b81c4da150d363e16ab08481783b378c081eac2da6f9bd69a920",
            None,
            Err(AeadDecryptionTagMissmatch),
            "42513dc22efb76c633e16c358f63303e", // The `7` in the middle should be an `8`
            GCM::new(vec![0xb3, 0x16, 0x61, 0xcc, 0x47, 0xbe])
        );
    }
}
