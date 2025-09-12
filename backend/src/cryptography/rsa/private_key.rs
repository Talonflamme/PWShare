use num_bigint::BigUint;
use std::fmt::{Debug, Display};
use crate::cryptography::rsa::PublicKey;

// TODO: add bits field
#[derive(Debug)]
pub struct PrivateKey {
    pub n: BigUint,
    pub d: BigUint,
    pub e: BigUint,
    pub p: BigUint,
    pub q: BigUint,
}

impl PrivateKey {
    pub fn new(n: BigUint, d: BigUint, e: BigUint, p: BigUint, q: BigUint) -> Self {
        Self { n, d, e, p, q }
    }

    pub fn decode(&self, message_cipher: BigUint) -> BigUint {
        assert!(
            self.n > message_cipher,
            "ciphertext representative out of range"
        );

        message_cipher.modpow(&self.d, &self.n)
    }
    
    pub fn public(&self) -> PublicKey {
        PublicKey { n: self.n.clone(), e: self.e.clone() }
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
