use crypto_bigint::{CheckedMul, NonZero, Uint, Word};

fn convert_uint<const L: usize, const M: usize>(x: &Uint<L>) -> Uint<M> {
    let words = x.as_words();
    let mut output: [Word; M] = [0; M];

    for i in 0..L {
        if i < M {
            output[i] = words[i];
        } else {
            assert!(words[i] == 0, "Value to large to convert into smaller Uint.");
        }
    }

    Uint::from_words(output)
}

/// Computes the least common multiple of `a` and `b`.
pub fn lcm<const L: usize>(a: Uint<L>, b: Uint<L>) -> Uint<L> {
    let product: Uint<L> = a.checked_mul(&b).unwrap();
    let gcd = gcd(a, b);

    product.checked_div(&gcd).expect("Divide by zero")
}

/// Computes the greatest common denominator of `a` and 
pub fn gcd<const L: usize>(mut a: Uint<L>, mut b: Uint<L>) -> Uint<L> {
    if a < b {
        let temp = a;
        a = b;
        b = temp;
    }

    while b != Uint::ZERO {
        let temp = b;
        b = a % NonZero::new(b).unwrap();
        a = temp;
    }

    a
}
