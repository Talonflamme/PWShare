use num_bigint::BigUint;

#[derive(Debug, Clone)]
pub struct ECPoint {
    pub x: BigUint,
    pub y: BigUint,
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
    /// Curve constant `a` as in `y² = x³ + ax + b (mod p)`.
    pub a: BigUint,
    /// Curve constant `b` as in `y² = x³ + ax + b (mod p)`. This might be unused for
    /// Montgomery curves like X25519 and X448.
    pub b: BigUint,
    /// Base point order `n`.
    pub n: BigUint,
    /// The Prime `p`.
    pub p: BigUint,
}
