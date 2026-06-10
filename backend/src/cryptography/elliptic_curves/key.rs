use super::curve::{EllipticCurve, Point};
use crypto_bigint::{BoxedUint, RandomMod};

pub struct ECDHPublicKey {
    /// The public key `A` that is used for the ECDH. The public key is calculated with `A = a * G`.
    pub key: Point,
}

pub struct ECDHPrivateKey {
    /// The private key `a` that is used for the ECDH. The public key is calculated
    /// with `A = a * G`.
    pub key: BoxedUint,
}

impl ECDHPrivateKey {
    pub fn generate(curve: &EllipticCurve) -> Self {
        loop {
            // [0; n - 1]
            let key = BoxedUint::random_mod_vartime(&mut rand::rng(), curve.n.as_nz_ref());

            if !bool::from(key.is_zero()) {
                return Self { key }; // [1; n - 1]
            }
        }
    }

    pub fn public(&self, curve: &EllipticCurve) -> ECDHPublicKey {
        let key = curve.scalar_multiply(&self.key, curve.G.clone());
        ECDHPublicKey { key }
    }
}
