use num_bigint::BigUint;
use num_traits::One;
use crate::cryptography::rsa::modular_arithmetic::ModularArithmetic;

#[derive(Debug, Clone)]
pub struct ECPoint {
    pub x: BigUint,
    pub y: BigUint,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub enum EllipticCurveConstants {
    /// Curves like `X25519` and `X448`. Using the form `y² = x³ + Ax² + x`
    Montgomery {
        /// The `A` parameter of the Montgomery curve `y² = x³ + Ax² + x`
        A: BigUint,
    },
    /// Curves in the Weierstrass representation like `SECP256R1` or `SECP384R1`
    Weierstrass {
        /// The `a` parameter of `y² = x³ + ax + b`
        a: BigUint,
        /// The `b` parameter of `y² = x³ + ax + b`
        b: BigUint,
    },
}

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct EllipticCurve {
    /// How many bytes each coordinate is encoded in. This is the same as
    /// `ceil(PrimeFieldSize / 8)`. For `X25519`, this is for example equal
    /// to `ceil(255 / 8) = 32`.
    pub coordinate_length: usize,
    /// The base point `G`, also Generator Point.
    pub G: ECPoint,
    pub constants: EllipticCurveConstants,
    /// Base point order `n`.
    pub n: BigUint,
    /// The Prime `p`.
    pub p: BigUint,
}

#[allow(non_snake_case)]
impl EllipticCurve {
    pub fn scalar_multiply(&self, scalar: &BigUint, point: ECPoint) -> BigUint {
        match &self.constants {
            EllipticCurveConstants::Montgomery { A } => {
                self.scalar_multiply_montgomery(scalar, point, A)
            }
            EllipticCurveConstants::Weierstrass { a, b } => {
                todo!()
            }
        }
    }

    fn scalar_multiply_montgomery(&self, scalar: &BigUint, point: ECPoint, A: &BigUint) -> BigUint {
        let x_1 = point.x.clone();
        let mut x_2 = BigUint::one();
        let mut z_2 = BigUint::ZERO;
        let mut x_3 = point.x;
        let mut z_3 = BigUint::one();
        let mut swap = false;
        let bits = self.n.bits();
        let two = BigUint::from(2u32);

        let a24 = (A - &two) / BigUint::from(4u8);
        let p = &self.p;

        macro_rules! cswap {
            ($swap:ident, $a:ident, $b:ident) => {
                if $swap {
                    ($b, $a)
                } else {
                    ($a, $b)
                }
            };
        }

        for t in (0..bits).rev() {
            let k_t = scalar.bit(t);
            swap ^= k_t;
            (x_2, x_3) = cswap!(swap, x_2, x_3);
            (z_2, z_3) = cswap!(swap, z_2, z_3);
            swap = k_t;

            let A = x_2.addm(&z_2, p);
            let AA = A.modpow(&two, p);

            let B = x_2.subm(&z_2, p);
            let BB = B.modpow(&two, p);

            let E = AA.subm(&BB, p);
            let C = x_3.addm(&z_3, p);
            let D = x_3.subm(&z_3, p);
            let DA = D.mulm(&A, p);
            let CB = C.mulm(&B, p);

            x_3 = DA.addm(&CB, p).modpow(&two, p);
            z_3 = x_1.mulm(&DA.subm(&CB, p).modpow(&two, p), p);
            x_2 = AA.mulm(&BB, p);
            z_2 = E.mulm(&AA.addm(&a24, p).mulm(&E, p), p);
        }

        (x_2, x_3) = cswap!(swap, x_2, x_3);
        (z_2, z_3) = cswap!(swap, z_2, z_3);

        x_2.mulm(&z_2.modpow(&(p - two), p), p)
    }
}
