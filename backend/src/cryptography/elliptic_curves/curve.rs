use crypto_bigint::{BoxedUint, Choice, CtEq, Odd, One, Zero};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Point {
    pub x: BoxedUint,
    pub y: BoxedUint,
}

/// Jacobian projective point: (X : Y : Z) maps to affine (X/Z², Y/Z³).
/// The point at infinity is represented by Z == 0.
/// TODO: consider migrating to `Uint<L>` (fixed-width) for hot-path arithmetic
/// once the curve-dispatch story is settled.
#[derive(Debug, Clone)]
struct JPoint {
    x: BoxedUint,
    y: BoxedUint,
    z: BoxedUint,
}

impl JPoint {
    fn infinity(bits_precision: u32) -> Self {
        Self {
            x: BoxedUint::one_with_precision(bits_precision),
            y: BoxedUint::one_with_precision(bits_precision),
            z: BoxedUint::zero_with_precision(bits_precision),
        }
    }

    fn is_infinity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Lift an affine point to Jacobian with Z = 1.
    fn from_affine(p: Point) -> Self {
        Self {
            z: BoxedUint::one_like(&p.x),
            x: p.x,
            y: p.y,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub enum EllipticCurveConstants {
    /// Curves like `X25519` and `X448`. Using the form `y² = x³ + Ax² + x`
    Montgomery {
        /// The `A` parameter of the Montgomery curve `y² = x³ + Ax² + x`
        A: BoxedUint,
        /// `(A - 2) / 4`
        A_minus2_over4: BoxedUint,
    },
    /// Curves in the Weierstrass representation like `SECP256R1` or `SECP384R1`
    Weierstrass {
        /// The `a` parameter of `y² = x³ + ax + b`
        a: BoxedUint,
        /// The `b` parameter of `y² = x³ + ax + b`
        b: BoxedUint,
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
    pub n: Odd<BoxedUint>,
    /// The Prime `p`. All arithmetic happens modulo `p`.
    pub p: Odd<BoxedUint>,
}

// TODO: make time constant?
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
    /// Returns a `BoxedUint` with the given small value, widened to match
    /// the curve's field precision. Use this whenever constructing small
    /// constants (2, 3, 4, 8, …) for use in field arithmetic.
    fn uint(&self, val: u64) -> BoxedUint {
        BoxedUint::from_words_with_precision([val], (self.coordinate_length * 8) as u32)
    }

    pub fn scalar_multiply(&self, scalar: &BoxedUint, point: Point) -> Point {
        match &self.constants {
            EllipticCurveConstants::Montgomery { .. } => Point {
                x: self.scalar_multiply_montgomery(scalar, point.x),
                y: BoxedUint::zero_like(scalar), // For montgomery curves, only the X coordinate is used
            },
            EllipticCurveConstants::Weierstrass { .. } => {
                self.scalar_multiply_weierstrass(scalar, point)
            }
        }
    }

    pub fn is_on_curve(&self, Point { x, y }: Point) -> bool {
        let three = self.uint(3);
        let p = &self.p;
        let p_nz = p.as_nz_ref();

        match &self.constants {
            EllipticCurveConstants::Montgomery {
                A,
                A_minus2_over4: _,
            } => {
                // y² = x³ + Ax² + x
                let x_squared = x.square_mod(p_nz);
                let x_cubed = x_squared.mul_mod(&x, p_nz);
                let a_x_squared = A.mul_mod(&x_squared, p_nz);

                let rhs = x_cubed.add_mod(&a_x_squared, p_nz).add_mod(&x, p_nz);
                let lhs = y.square_mod(p_nz);
                bool::from(lhs.ct_eq(&rhs))
            }
            EllipticCurveConstants::Weierstrass { a, b } => {
                // y² = x³ + ax + b
                let x_cubed = x.pow_mod(&three, p);
                let a_x = a.mul_mod(&x, p_nz);

                let rhs = x_cubed.add_mod(&a_x, p_nz).add_mod(b, p_nz);
                let lhs = y.square_mod(p_nz);
                bool::from(lhs.ct_eq(&rhs))
            }
        }
    }

    /// Multiplies a scalar `scalar` with the point on this curve whose x coordinate is `u`.
    /// Returns the x coordinate of the resulting point `P`. Implementation for Montgomery
    /// curves, panics if it isn't one.
    fn scalar_multiply_montgomery(&self, scalar: &BoxedUint, u: BoxedUint) -> BoxedUint {
        let EllipticCurveConstants::Montgomery {
            A: _,
            A_minus2_over4,
        } = &self.constants
        else {
            panic!("expected montgomery constants");
        };

        let two = self.uint(2);
        let p = &self.p;
        let p_nz = p.as_nz_ref();

        println!("p={}", p);
        println!("u={}", u);
        println!("u>=p {}", &u >= p.as_ref());

        let x_1 = u.clone();
        let mut x_2 = BoxedUint::one_like(scalar);
        let mut z_2 = BoxedUint::zero_like(scalar);
        let mut x_3 = u;
        let mut z_3 = BoxedUint::one_like(scalar);
        let mut swap = false;

        for t in (0..(self.coordinate_length * 8) as u32).rev() {
            let k_t = scalar.bit_vartime(t); // TODO: scalar is secret in ECDHE
            swap ^= k_t;
            (x_2, x_3) = cswap!(swap, x_2, x_3);
            (z_2, z_3) = cswap!(swap, z_2, z_3);
            swap = k_t;

            let A = x_2.add_mod(&z_2, p_nz);
            let AA = A.square_mod(p_nz);

            let B = x_2.sub_mod(&z_2, p_nz);
            let BB = B.square_mod(p_nz);

            let E = AA.sub_mod(&BB, p_nz);
            let C = x_3.add_mod(&z_3, p_nz);
            let D = x_3.sub_mod(&z_3, p_nz);
            let DA = D.mul_mod(&A, p_nz);
            let CB = C.mul_mod(&B, p_nz);

            x_3 = DA.add_mod(&CB, p_nz).square_mod(p_nz);
            z_3 = x_1.mul_mod(&DA.sub_mod(&CB, p_nz).square_mod(p_nz), p_nz);
            x_2 = AA.mul_mod(&BB, p_nz);
            z_2 = E.mul_mod(&AA.add_mod(&A_minus2_over4.mul_mod(&E, p_nz), p_nz), p_nz);
        }

        (x_2, _) = cswap!(swap, x_2, x_3);
        (z_2, _) = cswap!(swap, z_2, z_3);

        // x_2 * z_2^(p-2) mod p  (Fermat inverse)
        let p_minus_2 = p.as_ref() - two;
        x_2.mul_mod(&z_2.pow_mod(&p_minus_2, p), p_nz)
    }

    /// Convert a Jacobian point back to affine coordinates.
    /// Performs one modular inversion (Z⁻¹) via Fermat's little theorem: Z^(p-2) mod p.
    fn to_affine(&self, j: &JPoint) -> Point {
        let p = &self.p;
        let p_nz = p.as_nz_ref();
        let two = self.uint(2);

        // Z_inv = Z^(p-2) mod p
        let p_minus_2 = p.as_ref() - two;
        let z_inv = j.z.pow_mod(&p_minus_2, p);
        let z_inv2 = z_inv.square_mod(p_nz);
        let z_inv3 = z_inv2.mul_mod(&z_inv, p_nz);

        Point {
            x: j.x.mul_mod(&z_inv2, p_nz),
            y: j.y.mul_mod(&z_inv3, p_nz),
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
        if bool::from(j.is_infinity()) {
            return JPoint::infinity((self.coordinate_length * 8) as u32);
        }

        let p = &self.p;
        let p_nz = p.as_nz_ref();

        let EllipticCurveConstants::Weierstrass { a, .. } = &self.constants else {
            unreachable!("jdouble called on non-Weierstrass curve");
        };

        let two = self.uint(2);
        let three = self.uint(3);
        let four = self.uint(4);
        let eight = self.uint(8);

        let x = &j.x;
        let y = &j.y;
        let z = &j.z;

        let y2 = y.mul_mod(y, p_nz); // Y²
        let s = x.mul_mod(&y2, p_nz).mul_mod(&four, p_nz); // 4·X·Y²
        let x2 = x.mul_mod(x, p_nz); // X²
        let z2 = z.mul_mod(z, p_nz); // Z²
        let z4 = z2.mul_mod(&z2, p_nz); // Z⁴
        let m = x2
            .mul_mod(&three, p_nz)
            .add_mod(&a.mul_mod(&z4, p_nz), p_nz); // 3·X² + a·Z⁴
        let x3 = m.mul_mod(&m, p_nz).sub_mod(&s.mul_mod(&two, p_nz), p_nz); // M² - 2·S
        let y4 = y2.mul_mod(&y2, p_nz); // Y⁴
        let y3 = m
            .mul_mod(&s.sub_mod(&x3, p_nz), p_nz)
            .sub_mod(&y4.mul_mod(&eight, p_nz), p_nz); // M·(S-X') - 8·Y⁴
        let z3 = y.mul_mod(z, p_nz).mul_mod(&two, p_nz); // 2·Y·Z

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
        if bool::from(lhs.is_infinity()) {
            return rhs.clone();
        }
        if bool::from(rhs.is_infinity()) {
            return lhs.clone();
        }

        let p = &self.p;
        let p_nz = p.as_nz_ref();
        let two = self.uint(2);

        let z1_2 = lhs.z.mul_mod(&lhs.z, p_nz); // Z1²
        let z2_2 = rhs.z.mul_mod(&rhs.z, p_nz); // Z2²
        let u1 = lhs.x.mul_mod(&z2_2, p_nz); // X1·Z2²
        let u2 = rhs.x.mul_mod(&z1_2, p_nz); // X2·Z1²
        let s1 = lhs.y.mul_mod(&z2_2, p_nz).mul_mod(&rhs.z, p_nz); // Y1·Z2³
        let s2 = rhs.y.mul_mod(&z1_2, p_nz).mul_mod(&lhs.z, p_nz); // Y2·Z1³
        let h = u2.sub_mod(&u1, p_nz); // U2 - U1
        let r = s2.sub_mod(&s1, p_nz); // S2 - S1

        // Degenerate cases (not reached in the Montgomery ladder hot path).
        if bool::from(h.is_zero()) {
            return if bool::from(r.is_zero()) {
                self.jdouble(lhs) // lhs == rhs
            } else {
                JPoint::infinity((self.coordinate_length * 8) as u32) // lhs == -rhs
            };
        }

        let h2 = h.mul_mod(&h, p_nz); // H²
        let h3 = h2.mul_mod(&h, p_nz); // H³
        let u1h2 = u1.mul_mod(&h2, p_nz); // U1·H²
        let x3 = r
            .mul_mod(&r, p_nz)
            .sub_mod(&h3, p_nz)
            .sub_mod(&u1h2.mul_mod(&two, p_nz), p_nz); // R² - H³ - 2·U1·H²
        let y3 = r
            .mul_mod(&u1h2.sub_mod(&x3, p_nz), p_nz)
            .sub_mod(&s1.mul_mod(&h3, p_nz), p_nz); // R·(U1·H² - X') - S1·H³
        let z3 = h.mul_mod(&lhs.z, p_nz).mul_mod(&rhs.z, p_nz); // H·Z1·Z2

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
    pub fn scalar_multiply_weierstrass(&self, scalar: &BoxedUint, point: Point) -> Point {
        // Scalar == 0  →  caller should not reach here in a real protocol,
        // but we handle it gracefully.
        if bool::from(scalar.is_zero()) {
            // Return a sentinel; the caller must not use this as a shared secret.
            return Point {
                x: BoxedUint::zero_with_precision((self.coordinate_length * 8) as u32),
                y: BoxedUint::zero_with_precision((self.coordinate_length * 8) as u32),
            };
        }

        let jp = JPoint::from_affine(point);
        let mut r0 = JPoint::infinity((self.coordinate_length * 8) as u32); // 0·P
        let mut r1 = jp; // 1·P

        // Iterate from the most-significant bit down to bit 0.
        let bit_len = self.n.bits_precision();

        for i in (0..bit_len).rev() {
            // TODO: scalar is private and this operation must be kept private
            let bit = scalar.bit_vartime(i); // 0 or 1, derived from public scalar

            (r0, r1) = cswap!(bit, r0, r1);
            r1 = self.jadd(&r0, &r1);
            r0 = self.jdouble(&r0);
            (r0, r1) = cswap!(bit, r0, r1);
        }

        self.to_affine(&r0)
    }
}
