use crate::cryptography::elliptic_curves::curve::*;
use crate::tls::record::key_exchange::ecdhe::elliptic_curve::NamedCurve;
use crate::util::bytes_from_hex;
use num_bigint::BigUint;
use num_traits::{Num, One};
use std::str::FromStr;

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
fn test_x448_params() {
    let curve = NamedCurve::X448.curve().unwrap();

    let two = BigUint::from(2u8);

    assert_eq!(curve.coordinate_length, 56);
    assert_eq!(curve.p, two.pow(448) - two.pow(224) - BigUint::one());
    assert_eq!(
        curve.n,
        two.pow(446)
            - BigUint::from_str_radix(
                "8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d",
                16
            )
            .unwrap()
    );
    assert_eq!(curve.G.x, BigUint::from(5_u32));

    if let EllipticCurveConstants::Montgomery { A } = &curve.constants {
        assert_eq!(A, &BigUint::from(0x262a6_u32));
    } else {
        assert!(false, "X448 should be in Montgomery form");
    }
}

#[test]
fn test_x25519_scalar_multiply() {
    let curve = NamedCurve::X25519.curve().unwrap();

    let scalar = BigUint::from_str(
        "31029842492115040904895560451863089656472772604678260265531221036453811406496",
    )
    .unwrap();
    let u = BigUint::from_str(
        "34426434033919594451155107781188821651316167215306631574996226621102155684838",
    )
    .unwrap();

    let point = Point {
        x: u,
        y: BigUint::ZERO,
    };

    let output = curve.scalar_multiply(&scalar, point).x;

    let expected_output = BigUint::from_bytes_le(&bytes_from_hex(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ));

    assert_eq!(output, expected_output);
}

#[test]
fn test_secp256r1_scalar_multiply() {
    let curve = NamedCurve::SECP256R1.curve().unwrap();

    let scalar = BigUint::from_str_radix(
        "a0bf9fce83ee15eba6b984cb12530c4e57d7642d65bca02b92d6d1fa097552b",
        16,
    )
    .unwrap();

    let point = Point {
        x: BigUint::from_str_radix(
            "3c765b26361b7d686f0ea44edc283a6ab54d874ad64c67c312e4bd48db737392",
            16,
        )
        .unwrap(),
        y: BigUint::from_str_radix(
            "c42a4820da897f66821880301719725ec507e2b746505820263ac8c6a4847476",
            16,
        )
        .unwrap(),
    };

    let output = curve.scalar_multiply(&scalar, point);

    let expected_output = Point {
        x: BigUint::from_str_radix(
            "291ccd6c75909645e336aa17cb9533a55bcf5f1185dd5c33c4eee1681774cb35",
            16,
        )
        .unwrap(),
        y: BigUint::from_str_radix(
            "377c86bbe300a2378143da3267fa3f30c150b4ab4d6bf1564a6f5c2fc0f7796e",
            16,
        )
        .unwrap(),
    };

    assert_eq!(output, expected_output);
}
