use crate::cryptography::aes::aes::AES;
use crate::cryptography::aes::sbox::SBOX;
use crate::cryptography::rng::rng;
use rand::RngCore;
use std::fmt::{Debug, Display, Formatter};

pub trait AESKey: Clone + Debug {
    const VARIANT: AES;
    /// N is the length of the key in 32-bit words
    const N: usize;
    /// Amount of round keys used in the variant. Same as `VARIANT.num_rounds() + 1`
    const R: usize;

    /// Generate all round keys of this key. This vec has the output length of `R`.
    fn generate_round_keys(&self) -> Vec<u128>;

    fn from_be_hex(s: &str) -> Self;
}

/// This is part of the round constant `rcon`, which is defined as the 32-bit word:
/// rcon<sub>i</sub> = [rc<sub>i</sub>, 0x00 0x00 0x00]
/// AES-128 uses up to rcon<sub>10</sub>, AES-192 up to rcon<sub>8</sub> & AES-256 up to rcon<sub>7</sub>.
/// This array stores rcon<sub>1</sub> through rcon<sub>10</sub>. Hence, index 0 is rcon<sub>1</sub>
const RC: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

const fn get_rcon_i(i: usize) -> u32 {
    if i == 0 {
        panic!("rcon_0 does not exist. It exists from rcon_1 to rcon_10");
    }

    (RC[i - 1] as u32) << 24
}

fn sub_word(word: u32) -> u32 {
    // apply sbox for each byte
    (SBOX[(word >> 24) as usize] as u32) << 24
        | ((SBOX[(word >> 16 & 0xff) as usize] as u32) << 16)
        | ((SBOX[(word >> 8 & 0xff) as usize] as u32) << 8)
        | (SBOX[(word & 0xff) as usize] as u32)
}

fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

macro_rules! impl_aes_key {
    ($name:ident, $bits:expr, $variant:expr) => {
        #[derive(Copy, Clone)]
        pub struct $name {
            pub key: [u32; Self::N],
        }

        impl $name {
            pub const BYTES: usize = $bits / 8;

            pub fn new_random() -> Self {
                let mut key = [0; Self::N];

                for v in key.iter_mut() {
                    *v = rng!().next_u32();
                }

                Self::new(key)
            }

            pub fn new(key: [u32; Self::N]) -> Self {
                Self { key }
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
                write!(f, "0x");
                for u in self.key {
                    write!(f, "{:08x}", u)?;
                }

                Ok(())
            }
        }
        
        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                Display::fmt(self, f)
            }
        }

        impl AESKey for $name {
            const VARIANT: AES = $variant;
            const N: usize = $bits / 32;
            const R: usize = $variant.num_rounds() + 1;

            /// Generate all round keys based ont he original key.
            fn generate_round_keys(&self) -> Vec<u128> {
                let mut w: [u32; 4 * Self::R] = [0; 4 * Self::R];

                let original_words = self.key; // K_0 to K_N-1

                // Compute the words W_0 to W_4R-1
                for i in 0..(4 * Self::R) {
                    w[i] = if i < Self::N {
                        original_words[i]
                    } else if i % Self::N == 0 {
                        let rcon = get_rcon_i(i / Self::N);
                        w[i - Self::N] ^ sub_word(rot_word(w[i - 1])) ^ rcon
                    } else if Self::N > 6 && i % Self::N == 4 {
                        w[i - Self::N] ^ sub_word(w[i - 1])
                    } else {
                        w[i - Self::N] ^ w[i - 1]
                    }
                }

                // Combine W into RK
                let mut round_keys = Vec::with_capacity(Self::R);

                for i in 0..Self::R {
                    round_keys.push(
                        (w[4 * i] as u128) << 96
                            | (w[4 * i + 1] as u128) << 64
                            | (w[4 * i + 2] as u128) << 32
                            | (w[4 * i + 3] as u128),
                    );
                }

                round_keys
            }

            fn from_be_hex(s: &str) -> Self {
                assert_eq!(s.len(), Self::N * 8);

                let mut words = [0; Self::N];

                for i in 0..Self::N {
                    words[i] = u32::from_str_radix(&s[i * 8..(i + 1) * 8], 16).unwrap();
                }

                Self::new(words)
            }
        }
    };
}

impl_aes_key!(AESKey128, 128, AES::AES128);
impl_aes_key!(AESKey192, 192, AES::AES192);
impl_aes_key!(AESKey256, 256, AES::AES256);
