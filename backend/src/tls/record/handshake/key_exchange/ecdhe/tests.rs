use crate::tls::record::key_exchange::ecdhe::elliptic_curve::{NamedCurve, PointConversionForm};
use num_bigint::BigUint;
use num_traits::Num;

#[test]
fn test_x25519_params() {
    let curve = NamedCurve::X25519.curve().unwrap();

    assert_eq!(curve.name, NamedCurve::X25519);
    assert_eq!(curve.coordinate_length, 32);
    assert_eq!(curve.p, BigUint::from(2u8).pow(255) - BigUint::from(19u8));
    assert_eq!(
        curve.n,
        BigUint::from(2u8).pow(252)
            + BigUint::from_str_radix("14def9dea2f79cd65812631a5cf5d3ed", 16).unwrap()
    );
    assert_eq!(curve.a, BigUint::from(486662u32));
    assert_eq!(curve.G.point.form, PointConversionForm::Uncompressed);
    assert_eq!(curve.G.point.x, BigUint::from(9u32));
}
