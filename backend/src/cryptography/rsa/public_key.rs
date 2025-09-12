use num_bigint::BigUint;
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub struct PublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

impl PublicKey {
    pub fn new(n: BigUint, e: BigUint) -> Self {
        Self { n, e }
    }

    pub fn encrypt(&self, message_plain: BigUint) -> BigUint {
        assert!(
            self.n > message_plain,
            "Message representative out of range. m must be < n"
        );

        message_plain.modpow(&self.e, &self.n)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.n, self.e)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.e == other.e
    }
}

impl Eq for PublicKey {}
