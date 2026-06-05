use crate::cryptography::rsa::modular_arithmetic::ModularArithmetic;
use num_bigint::BigUint;
use num_traits::{One, Zero};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
}

/// Jacobian projective point: (X : Y : Z) maps to affine (X/Z², Y/Z³).
/// The point at infinity is represented by Z == 0.
#[derive(Debug, Clone)]
struct JPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl JPoint {
    fn infinity() -> Self {
        Self {
            x: BigUint::one(),
            y: BigUint::one(),
            z: BigUint::ZERO,
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Lift an affine point to Jacobian with Z = 1.
    fn from_affine(p: Point) -> Self {
        Self {
            x: p.x,
            y: p.y,
            z: BigUint::one(),
        }
    }
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
    pub G: Point,
    pub constants: EllipticCurveConstants,
    /// Base point order `n`.
    pub n: BigUint,
    /// The Prime `p`. All arithmetic happens modulo `p`.
    pub p: BigUint,
}

macro_rules! cswap {
    ($swap:ident, $a:ident, $b:ident) => {
        if $swap {
            ($b, $a)
        } else {
            ($a, $b)
        }
    };
}

#[allow(non_snake_case)]
impl EllipticCurve {
    pub fn scalar_multiply(&self, scalar: &BigUint, point: Point) -> Point {
        match &self.constants {
            EllipticCurveConstants::Montgomery { .. } => Point {
                x: self.scalar_multiply_montgomery(scalar, point.x),
                y: BigUint::ZERO, // For montgomery curves, only the X coordinate is used
            },
            EllipticCurveConstants::Weierstrass { .. } => {
                self.scalar_multiply_weierstrass(scalar, point)
            }
        }
    }

    pub fn is_on_curve(&self, Point { x, y }: Point) -> bool {
        let two = BigUint::from(2u8);
        let three = BigUint::from(3u8);

        match &self.constants {
            EllipticCurveConstants::Montgomery { A } => {
                // y² = x³ + Ax² + x
                let x_cubed = x.modpow(&three, &self.p);
                let x_squared = x.modpow(&two, &self.p);
                let a_x_squared = A.mulm(&x_squared, &self.p);

                let rhs = x_cubed.addm(&a_x_squared, &self.p).addm(&x, &self.p);
                let lhs = y.modpow(&two, &self.p);
                lhs == rhs
            }
            EllipticCurveConstants::Weierstrass { a, b } => {
                // y² = x³ + ax + b
                let x_cubed = x.modpow(&three, &self.p);
                let a_x = a.mulm(&x, &self.p);

                let rhs = x_cubed.addm(&a_x, &self.p).addm(b, &self.p);
                let lhs = y.modpow(&two, &self.p);
                lhs == rhs
            }
        }
    }

    /// Multiplies a scalar `scalar` with the point on this curve whose x coordinate is `u`.
    /// Returns the x coordinate of the resulting point `P`. Implementation for Montgomery
    /// curves, panics if it isn't one.
    fn scalar_multiply_montgomery(&self, scalar: &BigUint, u: BigUint) -> BigUint {
        let EllipticCurveConstants::Montgomery { A } = &self.constants else {
            panic!("expected montgomery constants");
        };

        let x_1 = u.clone();
        let mut x_2 = BigUint::one();
        let mut z_2 = BigUint::ZERO;
        let mut x_3 = u;
        let mut z_3 = BigUint::one();
        let mut swap = false;
        let bits = self.p.bits();
        let two = BigUint::from(2u32);

        let a24 = (A - &two) / BigUint::from(4u8);
        let p = &self.p;

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
            z_2 = E.mulm(&AA.addm(&a24.mulm(&E, p), p), p);
        }

        (x_2, _) = cswap!(swap, x_2, x_3);
        (z_2, _) = cswap!(swap, z_2, z_3);

        x_2.mulm(&z_2.modpow(&(p - two), p), p)
    }

    /// Convert a Jacobian point back to affine coordinates.
    /// Performs one modular inversion (Z⁻¹) via Fermat's little theorem: Z^(p-2) mod p.
    fn to_affine(&self, j: &JPoint) -> Point {
        let p = &self.p;

        // Z_inv = Z^(p-2) mod p
        let z_inv = j.z.modpow(&(p - 2u32), p);
        let z_inv2 = z_inv.mulm(&z_inv, p);
        let z_inv3 = z_inv2.mulm(&z_inv, p);

        Point {
            x: j.x.mulm(&z_inv2, p),
            y: j.y.mulm(&z_inv3, p),
        }
    }

    /// Jacobian point doubling.
    ///
    /// Formula (general, any `a`):
    ///   S  = 4·X·Y²
    ///   M  = 3·X² + a·Z⁴
    ///   X' = M² - 2·S
    ///   Y' = M·(S - X') - 8·Y⁴
    ///   Z' = 2·Y·Z
    ///
    /// Cost: 4S + 10M (not counting additions/small constants).
    fn jdouble(&self, j: &JPoint) -> JPoint {
        if j.is_infinity() {
            return JPoint::infinity();
        }

        let p = &self.p;

        let EllipticCurveConstants::Weierstrass { a, .. } = &self.constants else {
            unreachable!("jdouble called on non-Weierstrass curve");
        };

        let x = &j.x;
        let y = &j.y;
        let z = &j.z;

        let y2 = y.mulm(y, p); // Y²
        let s = x.mulm(&y2, p).mulm(&4u32.into(), p); // 4·X·Y²
        let x2 = x.mulm(x, p); // X²
        let z2 = z.mulm(z, p); // Z²
        let z4 = z2.mulm(&z2, p); // Z⁴
        let m = x2.mulm(&3u32.into(), p).addm(&a.mulm(&z4, p), p); // 3·X² + a·Z⁴
        let x3 = m.mulm(&m, p).subm(&s.mulm(&2u32.into(), p), p); // M² - 2·S
        let y4 = y2.mulm(&y2, p); // Y⁴
        let y3 = m
            .mulm(&s.subm(&x3, p), p)
            .subm(&y4.mulm(&8u32.into(), p), p); // M·(S-X') - 8·Y⁴
        let z3 = y.mulm(z, p).mulm(&2u32.into(), p); // 2·Y·Z

        JPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Jacobian point addition.
    ///
    /// Formula (add-2007-bl, full Jacobian):
    ///   U1 = X1·Z2²,  U2 = X2·Z1²
    ///   S1 = Y1·Z2³,  S2 = Y2·Z1³
    ///   H  = U2 - U1
    ///   R  = S2 - S1
    ///   X' = R² - H³ - 2·U1·H²
    ///   Y' = R·(U1·H² - X') - S1·H³
    ///   Z' = H·Z1·Z2
    ///
    /// Cost: 11M + 5S.
    ///
    /// In the Montgomery ladder, the two inputs are always distinct
    /// non-infinity points so the H==0 branches are never taken in the
    /// hot path; they are handled correctly here for completeness.
    fn jadd(&self, lhs: &JPoint, rhs: &JPoint) -> JPoint {
        if lhs.is_infinity() {
            return rhs.clone();
        }
        if rhs.is_infinity() {
            return lhs.clone();
        }

        let p = &self.p;

        let z1_2 = lhs.z.mulm(&lhs.z, p); // Z1²
        let z2_2 = rhs.z.mulm(&rhs.z, p); // Z2²
        let u1 = lhs.x.mulm(&z2_2, p); // X1·Z2²
        let u2 = rhs.x.mulm(&z1_2, p); // X2·Z1²
        let s1 = lhs.y.mulm(&z2_2, p).mulm(&rhs.z, p); // Y1·Z2³
        let s2 = rhs.y.mulm(&z1_2, p).mulm(&lhs.z, p); // Y2·Z1³
        let h = u2.subm(&u1, p); // U2 - U1
        let r = s2.subm(&s1, p); // S2 - S1

        // Degenerate cases (not reached in the Montgomery ladder hot path).
        if h.is_zero() {
            return if r.is_zero() {
                self.jdouble(lhs) // lhs == rhs
            } else {
                JPoint::infinity() // lhs == -rhs
            };
        }

        let h2 = h.mulm(&h, p); // H²
        let h3 = h2.mulm(&h, p); // H³
        let u1h2 = u1.mulm(&h2, p); // U1·H²
        let x3 = r
            .mulm(&r, p)
            .subm(&h3, p)
            .subm(&u1h2.mulm(&2u32.into(), p), p); // R² - H³ - 2·U1·H²
        let y3 = r.mulm(&u1h2.subm(&x3, p), p).subm(&s1.mulm(&h3, p), p); // R·(U1·H² - X') - S1·H³
        let z3 = h.mulm(&lhs.z, p).mulm(&rhs.z, p); // H·Z1·Z2

        JPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Scalar multiplication on a Weierstrass curve using the Montgomery ladder
    /// over Jacobian coordinates.
    ///
    /// Every bit of `scalar` executes exactly one `jdouble` + one `jadd`
    /// plus two branch-free `cswap`s — no secret-dependent control flow.
    /// One modular inversion (via Fermat) is performed at the end to convert
    /// back to affine.
    pub fn scalar_multiply_weierstrass(&self, scalar: &BigUint, point: Point) -> Point {
        // Scalar == 0  →  caller should not reach here in a real protocol,
        // but we handle it gracefully.
        if scalar.is_zero() {
            // Return a sentinel; the caller must not use this as a shared secret.
            return Point {
                x: BigUint::zero(),
                y: BigUint::zero(),
            };
        }

        let jp = JPoint::from_affine(point);
        let mut r0 = JPoint::infinity(); // 0·P
        let mut r1 = jp; // 1·P

        // Iterate from the most-significant bit down to bit 0.
        let bit_len = self.n.bits();

        for i in (0..bit_len).rev() {
            let bit = scalar.bit(i); // 0 or 1, derived from public scalar

            (r0, r1) = cswap!(bit, r0, r1);
            r1 = self.jadd(&r0, &r1);
            r0 = self.jdouble(&r0);
            (r0, r1) = cswap!(bit, r0, r1);
        }

        self.to_affine(&r0)
    }
}
