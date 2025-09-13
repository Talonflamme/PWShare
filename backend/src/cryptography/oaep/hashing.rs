/// A trait that is implemented for a couple of HashFunctions.
pub trait HashFunction {
    // This function and `.block_size_bytes(&self)` are functions as the trait cannot be wrapped
    // using Box<dyn H> otherwise. So they can neither be Const, nor methods of the Trait itself (using
    // Self).
    /// The output length of this Hash Function in bytes.
    fn h_len(&self) -> u32;

    /// The block size of the hash function in bytes.
    fn block_size_bytes(&self) -> u32;

    fn hash(&self, message: &[u8]) -> Vec<u8>;
}

macro_rules! copy_chunk_into_words_u32 {
    ($chunk:expr, $words:expr) => {
        for i in 0..16 {
            $words[i] = (($chunk[i * 4] as u32) << 24)
                | (($chunk[i * 4 + 1] as u32) << 16)
                | (($chunk[i * 4 + 2] as u32) << 8)
                | ($chunk[i * 4 + 3] as u32);
        }
    };
}

macro_rules! copy_chunk_into_words_u64 {
    ($chunk:expr, $words:expr) => {
        for i in 0..16 {
            $words[i] = (($chunk[i * 8] as u64) << 56)
                | (($chunk[i * 8 + 1] as u64) << 48)
                | (($chunk[i * 8 + 2] as u64) << 40)
                | (($chunk[i * 8 + 3] as u64) << 32)
                | (($chunk[i * 8 + 4] as u64) << 24)
                | (($chunk[i * 8 + 5] as u64) << 16)
                | (($chunk[i * 8 + 6] as u64) << 8)
                | ($chunk[i * 8 + 7] as u64);
        }
    };
}

pub struct Sha1;

impl HashFunction for Sha1 {
    fn h_len(&self) -> u32 {
        20
    }

    fn block_size_bytes(&self) -> u32 {
        64
    }

    fn hash(&self, message: &[u8]) -> Vec<u8> {
        let mut h0 = 0x67452301_u32;
        let mut h1 = 0xEFCDAB89_u32;
        let mut h2 = 0x98BADCFE_u32;
        let mut h3 = 0x10325476_u32;
        let mut h4 = 0xC3D2E1F0_u32;

        let mut message = message.to_vec();

        let message_len_bits = (message.len() * 8) as u64;

        // append the bit 1
        message.push(0b10000000);

        // append 0 <= k <= 512 bits 0, such that the message len is congruent to 448
        while message.len() % 64 != 56 {
            message.push(0);
        }

        // append ml (message-len) as a 64-bit big-endian integer.
        // Thus, the message length becomes a multiple of 512
        message.extend_from_slice(&message_len_bits.to_be_bytes());

        // break message into 512-bit (=64 byte) chunks
        for chunk in message.chunks_exact(64) {
            // break chunk into 16 32-bit (=4 byte) big-endian words
            let mut w = [0u32; 80];

            copy_chunk_into_words_u32!(chunk, w);

            for i in 16..80 {
                let xor_result = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
                let rotated = xor_result.rotate_left(1);
                w[i] = rotated;
            }

            // initialize hash value for this chunk
            let mut a = h0;
            let mut b = h1;
            let mut c = h2;
            let mut d = h3;
            let mut e = h4;
            let mut f = 0u32;
            let mut k = 0u32;

            for i in 0..80 {
                match i {
                    0..20 => {
                        f = (b & c) | ((!b) & d);
                        k = 0x5A827999;
                    }
                    20..40 => {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    }
                    40..60 => {
                        f = (b & c) ^ (b & d) ^ (c & d);
                        k = 0x8F1BBCDC;
                    }
                    60..80 => {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }
                    _ => {}
                }

                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);

                e = d;
                d = c;
                c = b.rotate_right(2); // left-rotate 30
                b = a;
                a = temp;
            }

            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }

        let mut result = Vec::with_capacity(20);

        result.extend_from_slice(&h0.to_be_bytes());
        result.extend_from_slice(&h1.to_be_bytes());
        result.extend_from_slice(&h2.to_be_bytes());
        result.extend_from_slice(&h3.to_be_bytes());
        result.extend_from_slice(&h4.to_be_bytes());

        result
    }
}

const K_256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K_512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

macro_rules! sha256 {
    ($message:ident, $h0:ident, $h1:ident, $h2:ident, $h3:ident, $h4:ident, $h5:ident, $h6:ident, $h7:ident) => {
        for chunk in $message.chunks_exact(64) {
            let mut w: [u32; 64] = [0; 64];

            copy_chunk_into_words_u32!(chunk, w);

            for i in 16..64 {
                let s0 =
                    (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
                let s1 =
                    (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);

                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            // initialize working variables to current hash value
            let mut a = $h0;
            let mut b = $h1;
            let mut c = $h2;
            let mut d = $h3;
            let mut e = $h4;
            let mut f = $h5;
            let mut g = $h6;
            let mut h = $h7;

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K_256[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ (a.rotate_right(22));
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            $h0 = $h0.wrapping_add(a);
            $h1 = $h1.wrapping_add(b);
            $h2 = $h2.wrapping_add(c);
            $h3 = $h3.wrapping_add(d);
            $h4 = $h4.wrapping_add(e);
            $h5 = $h5.wrapping_add(f);
            $h6 = $h6.wrapping_add(g);
            $h7 = $h7.wrapping_add(h);
        }
    };
}

macro_rules! sha512 {
    ($message:ident, $h0:ident, $h1:ident, $h2:ident, $h3:ident, $h4:ident, $h5:ident, $h6:ident, $h7:ident) => {
        for chunk in $message.chunks_exact(128) {
            let mut w: [u64; 80] = [0; 80];

            copy_chunk_into_words_u64!(chunk, w);

            for i in 16..80 {
                let s0 =
                    (w[i - 15].rotate_right(1)) ^ (w[i - 15].rotate_right(8)) ^ (w[i - 15] >> 7);
                let s1 =
                    (w[i - 2].rotate_right(19)) ^ (w[i - 2].rotate_right(61)) ^ (w[i - 2] >> 6);

                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            // initialize working variables to current hash value
            let mut a = $h0;
            let mut b = $h1;
            let mut c = $h2;
            let mut d = $h3;
            let mut e = $h4;
            let mut f = $h5;
            let mut g = $h6;
            let mut h = $h7;

            for i in 0..80 {
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K_512[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ (a.rotate_right(39));
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            $h0 = $h0.wrapping_add(a);
            $h1 = $h1.wrapping_add(b);
            $h2 = $h2.wrapping_add(c);
            $h3 = $h3.wrapping_add(d);
            $h4 = $h4.wrapping_add(e);
            $h5 = $h5.wrapping_add(f);
            $h6 = $h6.wrapping_add(g);
            $h7 = $h7.wrapping_add(h);
        }
    };
}

pub struct Sha256;

impl HashFunction for Sha256 {
    fn h_len(&self) -> u32 {
        32
    }

    fn block_size_bytes(&self) -> u32 {
        64
    }

    fn hash(&self, message: &[u8]) -> Vec<u8> {
        let mut h0 = 0x6a09e667_u32;
        let mut h1 = 0xbb67ae85_u32;
        let mut h2 = 0x3c6ef372_u32;
        let mut h3 = 0xa54ff53a_u32;
        let mut h4 = 0x510e527f_u32;
        let mut h5 = 0x9b05688c_u32;
        let mut h6 = 0x1f83d9ab_u32;
        let mut h7 = 0x5be0cd19_u32;

        // Initialize array of round constants

        let mut message = message.to_vec();
        // Pre-Processing
        let message_len_bits = (message.len() * 8) as u64;
        message.push(0x80); // append bit '1'

        // append K '0' bits such that (L + 8 + K + 64) is a multiple of 512
        while message.len() % 64 != 56 {
            message.push(0);
        }

        // append L as a 64-bit big-endian integer
        message.extend_from_slice(&message_len_bits.to_be_bytes());

        sha256!(message, h0, h1, h2, h3, h4, h5, h6, h7);

        let mut result = Vec::with_capacity(64);

        result.extend_from_slice(&h0.to_be_bytes());
        result.extend_from_slice(&h1.to_be_bytes());
        result.extend_from_slice(&h2.to_be_bytes());
        result.extend_from_slice(&h3.to_be_bytes());
        result.extend_from_slice(&h4.to_be_bytes());
        result.extend_from_slice(&h5.to_be_bytes());
        result.extend_from_slice(&h6.to_be_bytes());
        result.extend_from_slice(&h7.to_be_bytes());

        result
    }
}

pub struct Sha224;

impl HashFunction for Sha224 {
    fn h_len(&self) -> u32 {
        28
    }

    fn block_size_bytes(&self) -> u32 {
        64
    }

    fn hash(&self, message: &[u8]) -> Vec<u8> {
        let mut h0 = 0xc1059ed8_u32;
        let mut h1 = 0x367cd507_u32;
        let mut h2 = 0x3070dd17_u32;
        let mut h3 = 0xf70e5939_u32;
        let mut h4 = 0xffc00b31_u32;
        let mut h5 = 0x68581511_u32;
        let mut h6 = 0x64f98fa7_u32;
        let mut h7 = 0xbefa4fa4_u32;

        let mut message = message.to_vec();
        // Pre-Processing
        let message_len_bits = (message.len() * 8) as u64;
        message.push(0x80); // append bit '1'

        // append K '0' bits such that (L + 8 + K + 64) is a multiple of 512
        while message.len() % 64 != 56 {
            message.push(0);
        }

        // append L as a 64-bit big-endian integer
        message.extend_from_slice(&message_len_bits.to_be_bytes());

        sha256!(message, h0, h1, h2, h3, h4, h5, h6, h7);

        let mut result = Vec::with_capacity(64);

        result.extend_from_slice(&h0.to_be_bytes());
        result.extend_from_slice(&h1.to_be_bytes());
        result.extend_from_slice(&h2.to_be_bytes());
        result.extend_from_slice(&h3.to_be_bytes());
        result.extend_from_slice(&h4.to_be_bytes());
        result.extend_from_slice(&h5.to_be_bytes());
        result.extend_from_slice(&h6.to_be_bytes());
        // omit h7

        result
    }
}

pub struct Sha512;

impl HashFunction for Sha512 {
    fn h_len(&self) -> u32 {
        64
    }

    fn block_size_bytes(&self) -> u32 {
        128
    }

    fn hash(&self, message: &[u8]) -> Vec<u8> {
        let mut h0 = 0x6a09e667f3bcc908_u64;
        let mut h1 = 0xbb67ae8584caa73b_u64;
        let mut h2 = 0x3c6ef372fe94f82b_u64;
        let mut h3 = 0xa54ff53a5f1d36f1_u64;
        let mut h4 = 0x510e527fade682d1_u64;
        let mut h5 = 0x9b05688c2b3e6c1f_u64;
        let mut h6 = 0x1f83d9abfb41bd6b_u64;
        let mut h7 = 0x5be0cd19137e2179_u64;

        let mut message = message.to_vec();
        // Pre-Processing
        let message_len_bits = (message.len() * 8) as u128;

        message.push(0x80); // append bit '1'

        // append K '0' bits such that (L + 8 + K + 128) is a multiple of 512
        while message.len() % 128 != 112 {
            message.push(0);
        }

        // append L as a 64-bit big-endian integer
        message.extend_from_slice(&message_len_bits.to_be_bytes());

        sha512!(message, h0, h1, h2, h3, h4, h5, h6, h7);

        let mut result = Vec::with_capacity(64);

        result.extend_from_slice(&h0.to_be_bytes());
        result.extend_from_slice(&h1.to_be_bytes());
        result.extend_from_slice(&h2.to_be_bytes());
        result.extend_from_slice(&h3.to_be_bytes());
        result.extend_from_slice(&h4.to_be_bytes());
        result.extend_from_slice(&h5.to_be_bytes());
        result.extend_from_slice(&h6.to_be_bytes());
        result.extend_from_slice(&h7.to_be_bytes());

        result
    }
}

pub struct Sha384;

impl HashFunction for Sha384 {
    fn h_len(&self) -> u32 {
        48
    }

    fn block_size_bytes(&self) -> u32 {
        128
    }

    fn hash(&self, message: &[u8]) -> Vec<u8> {
        let mut h0 = 0xcbbb9d5dc1059ed8_u64;
        let mut h1 = 0x629a292a367cd507_u64;
        let mut h2 = 0x9159015a3070dd17_u64;
        let mut h3 = 0x152fecd8f70e5939_u64;
        let mut h4 = 0x67332667ffc00b31_u64;
        let mut h5 = 0x8eb44a8768581511_u64;
        let mut h6 = 0xdb0c2e0d64f98fa7_u64;
        let mut h7 = 0x47b5481dbefa4fa4_u64;

        let mut message = message.to_vec();
        // Pre-Processing
        let message_len_bits = (message.len() * 8) as u128;

        message.push(0x80); // append bit '1'

        // append K '0' bits such that (L + 8 + K + 128) is a multiple of 512
        while message.len() % 128 != 112 {
            message.push(0);
        }

        // append L as a 64-bit big-endian integer
        message.extend_from_slice(&message_len_bits.to_be_bytes());

        sha512!(message, h0, h1, h2, h3, h4, h5, h6, h7);

        let mut result = Vec::with_capacity(48);

        result.extend_from_slice(&h0.to_be_bytes());
        result.extend_from_slice(&h1.to_be_bytes());
        result.extend_from_slice(&h2.to_be_bytes());
        result.extend_from_slice(&h3.to_be_bytes());
        result.extend_from_slice(&h4.to_be_bytes());
        result.extend_from_slice(&h5.to_be_bytes());

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::UintDisplay;

    fn hash(h: impl HashFunction, message: &str) -> String {
        h.hash(message.as_bytes()).hex()
    }

    #[test]
    fn sha1() {
        assert_eq!(
            hash(Sha1, "The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );

        assert_eq!(
            hash(Sha1, "The quick brown fox jumps over the lazy cog"),
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
        );

        assert_eq!(hash(Sha1, ""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        assert_eq!(Sha1.h_len() * 8, 160);
        assert_eq!(Sha1.block_size_bytes() * 8, 512);
    }

    #[test]
    fn sha256() {
        assert_eq!(
            hash(Sha256, ""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        assert_eq!(
            hash(Sha256, "abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        assert_eq!(
            hash(Sha256, "The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );

        assert_eq!(Sha256.h_len() * 8, 256);
        assert_eq!(Sha256.block_size_bytes() * 8, 512);
    }

    #[test]
    fn sha224() {
        assert_eq!(
            hash(Sha224, ""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );

        assert_eq!(
            hash(Sha224, "The quick brown fox jumps over the lazy dog"),
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"
        );

        assert_eq!(
            hash(Sha224, "The quick brown fox jumps over the lazy dog."),
            "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c"
        );

        assert_eq!(Sha224.h_len() * 8, 224);
        assert_eq!(Sha224.block_size_bytes() * 8, 512);
    }

    #[test]
    fn sha512() {
        assert_eq!(
            hash(Sha512, ""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );

        assert_eq!(
            hash(Sha512, "The quick brown fox jumps over the lazy dog"),
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
        );

        assert_eq!(Sha512.h_len() * 8, 512);
        assert_eq!(Sha512.block_size_bytes() * 8, 1024);
    }

    #[test]
    fn sha384() {
        assert_eq!(
            hash(Sha384, ""),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        assert_eq!(
            hash(Sha384, "The quick brown fox jumps over the lazy dog"),
            "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
        );

        assert_eq!(Sha384.h_len() * 8, 384);
        assert_eq!(Sha384.block_size_bytes() * 8, 1024);
    }
}
