use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use crate::cryptography::rng::rng;
use super::curve::{EllipticCurve, Point};

pub struct ECDHPublicKey {
    /// The public key `A` that is used for the ECDH. The public key is calculated with `A = a * G`.
    pub key: Point,
}

pub struct ECDHPrivateKey {
    /// The private key `a` that is used for the ECDH. The public key is calculated
    /// with `A = a * G`.
    pub key: BigUint,
}

impl ECDHPrivateKey {
    pub fn generate(curve: &EllipticCurve) -> Self {
        let key = rng!().gen_biguint_range(&BigUint::one(), &curve.n); // [1, n - 1]
        Self { key }
    }

    pub fn public(&self, curve: &EllipticCurve) -> ECDHPublicKey {
        let key = curve.scalar_multiply(&self.key, curve.G.clone());
        ECDHPublicKey { key }
    }
}
