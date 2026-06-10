use std::fmt::{Debug, Display};
use crypto_bigint::{BoxedUint, Odd};

#[derive(Debug)]
pub struct RSAPublicKey {
    pub n: Odd<BoxedUint>,
    pub e: BoxedUint,
}

impl RSAPublicKey {
    pub fn new(n: Odd<BoxedUint>, e: BoxedUint) -> Self {
        Self { n, e }
    }

    pub fn encrypt(&self, message_plain: BoxedUint) -> BoxedUint {
        assert!(
            self.n.as_ref() > &message_plain,
            "Message representative out of range. m must be < n"
        );

        message_plain.pow_mod(&self.e, &self.n)
    }
}

impl Display for RSAPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.n, self.e)
    }
}

impl PartialEq for RSAPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.e == other.e
    }
}

impl Eq for RSAPublicKey {}
