use crate::tls::record::variable_length_vec::VariableLengthVec;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, ReadableFromStream, WritableToSink)]
pub enum ECCurveType {
    // The values `explicit_prime = 1` and `explicit_char2 = 2` are deprecated by RFC 8422. Since
    // we only implement the Server, we can safely not implement and support these types.
    /// Indicates that a named curve is used. This option SHOULD be used when applicable.
    NamedCurve = 3,
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ECCurve {
    /// `a` parameter of the Elliptic Curve (EC) with `{(x, y) | y² = x³ + ax + b}`
    pub a: VariableLengthVec<u8, 1, 255>,
    /// `b` parameter of the Elliptic Curve (EC) with `{(x, y) | y² = x³ + ax + b}`
    pub b: VariableLengthVec<u8, 1, 255>,
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ECPoint {
    pub point: VariableLengthVec<u8, 1, 255>,
}

#[repr(u16)]
#[derive(Debug, ReadableFromStream, WritableToSink, Clone, Copy, PartialEq, Eq)]
#[fallback(Unknown)]
pub enum NamedCurve {
    SECP256R1 = 23,
    SECP384R1 = 24,
    SECP521R1 = 25,
    X25519 = 29,
    X448 = 30,
    Unknown,
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ECParameters {
    pub curve_type: ECCurveType,
    pub named_curve: NamedCurve,
}

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct ServerECDHParams {
    pub curve_params: ECParameters,
    pub public: ECPoint,
}
