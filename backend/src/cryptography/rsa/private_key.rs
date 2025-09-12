use crate::cryptography::rsa::PublicKey;
use crate::tls::Sink;
use num_bigint::BigUint;
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub struct PrivateKey {
    pub n: BigUint,
    pub d: BigUint,
    pub e: BigUint,
    pub p: BigUint,
    pub q: BigUint,
}

#[derive(Debug)]
pub struct DecryptError {
    reason: &'static str,
}

impl PrivateKey {
    pub fn new(n: BigUint, d: BigUint, e: BigUint, p: BigUint, q: BigUint) -> Self {
        Self { n, d, e, p, q }
    }

    pub fn decrypt(&self, message_cipher: BigUint) -> Result<BigUint, DecryptError> {
        if self.n <= message_cipher {
            Err(DecryptError {
                reason: "ciphertext representative out of range",
            })
        } else {
            Ok(message_cipher.modpow(&self.d, &self.n))
        }
    }

    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if ciphertext.len() != self.size_in_bytes() {
            return Err(DecryptError {
                reason: "len(C) != len(N)",
            });
        }

        let uint = BigUint::from_bytes_be(ciphertext);
        let plain = self.decrypt(uint)?;
        let plain_size = plain.bits().div_ceil(8) as usize;

        let mut result = vec![0; self.size_in_bytes() - plain_size];

        result.extend_from_slice(&plain.to_bytes_be());

        Ok(result)
    }

    pub fn public(&self) -> PublicKey {
        PublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }

    /// The size of the RSA modulus `n` in bytes.
    pub fn size_in_bytes(&self) -> usize {
        self.n.bits().div_ceil(8) as usize
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.n, self.d)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.d == other.d
    }
}

impl Eq for PrivateKey {}
