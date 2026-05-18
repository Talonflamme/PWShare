use std::str::FromStr;
use crate::cryptography::elliptic_curves::curve::*;
use crate::tls::record::key_exchange::ecdhe::elliptic_curve::{NamedCurve, PointConversionForm};
use num_bigint::BigUint;
use num_traits::Num;
use crate::util::bytes_from_hex;

#[test]
fn test_x25519_params() {
    let curve = NamedCurve::X25519.curve().unwrap();

    assert_eq!(curve.coordinate_length, 32);
    assert_eq!(curve.p, BigUint::from(2u8).pow(255) - BigUint::from(19u8));
    assert_eq!(
        curve.n,
        BigUint::from(2u8).pow(252)
            + BigUint::from_str_radix("14def9dea2f79cd65812631a5cf5d3ed", 16).unwrap()
    );
    assert_eq!(curve.G.x, BigUint::from(9u32));

    if let EllipticCurveConstants::Montgomery { A } = &curve.constants {
        assert_eq!(A, &BigUint::from(486662u32));
    } else {
        assert!(false, "X25519 should be in Montgomery form");
    }
}

#[test]
fn test_x25519_scalar_multiply() {
    let curve = NamedCurve::X25519.curve().unwrap();

    let scalar = BigUint::from_str("31029842492115040904895560451863089656472772604678260265531221036453811406496").unwrap();
    let u = BigUint::from_str("34426434033919594451155107781188821651316167215306631574996226621102155684838").unwrap();

    let point = ECPoint { x: u, y: BigUint::ZERO };

    let output = curve. scalar_multiply(&scalar, point);

    let expected_output = BigUint::from_bytes_le(&bytes_from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

    assert_eq!(output, expected_output);
}
