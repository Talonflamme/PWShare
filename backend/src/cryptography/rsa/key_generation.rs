use super::{rabin_miller::MillerRabinTest, RSAPrivateKey, Sieve};
use crypto_bigint::{BitOps, BoxedUint, Choice, Gcd, Odd, One, RandomBits};

/// Generate a prime number with the specified amount of bits.
/// `L` is the capacity of the Uint type.
/// `num_bits` is the actual amount of bits that are randomized. Hence, the `num_bits` least significant
/// bits are randomized. This means that `num_bits` must be <= L * 64.
fn generate_prime(num_bits: u64) -> Odd<BoxedUint> {
    // the only case that this loop actually uses a second iteration is if there is no prime between the randomly
    // selected start and Uint::MAX. This has a chance of ~10^-307 and will never happen.

    loop {
        let mut start: BoxedUint = BoxedUint::random_bits(&mut rand::rng(), num_bits as u32);
        start.set_bit(0, Choice::TRUE); // make it odd

        // Instead of checking every or every 2 possible primes, we use a Sieve, similar to the Sieve of Eratosthenes algorithm.
        // So we only call `is_prime` on candidates that are not divisible by any of the first 2048 primes.
        let sieve = Sieve::new(start, num_bits);

        for mut num in sieve {
            if is_prime(&mut num) {
                return num;
            }
        }
    }
}

/// Checks if the given `candidate` is likely to be prime.
/// Chance of a false-positive is less than 10^-6
fn is_prime(candidate: &mut Odd<BoxedUint>) -> bool {
    let rabin_miller = MillerRabinTest::new(candidate);
    rabin_miller.is_prime(None)
}

/// Generates two primes of the given size.
///
/// `key_size` - The amount of bits of the modulus n. The two primes will have up to half of
/// this amount of bits.
fn generate_p_and_q(key_size: u64) -> (Odd<BoxedUint>, Odd<BoxedUint>) {
    // this amount of bits is half of the actual key (two primes are multiplied, two 1024 bit primes make a 1024² = 2048 bit key)
    let bits = key_size / 2; // L * 64 = number of bits for value type, divide by 2 to get the private keys.
    let p = generate_prime(bits);
    let q = generate_prime(bits);

    (p, q)
}

/// Computes `λ(n)` with `n=pq` where λ is Carmichael's totient function. `p` and `q` are <i>assumed</i> to be prime.
/// Since `n=pq`, `λ(n) = lcm(λ(p), λ(q))` and since p and q are primes, `λ(p) = p - 1` and `λ(q) = q - 1`. Hence, `λ(n) = lcm(p - 1, q - 1)`.
fn compute_lambda(p: &BoxedUint, q: &BoxedUint) -> BoxedUint {
    let p_minus_1 = p - BoxedUint::one_like(p);
    let q_minus_1 = q - BoxedUint::one_like(q);

    let gcd = (&p_minus_1).gcd(&q_minus_1).into_nz().unwrap();
    let lcm = p_minus_1 / gcd * q_minus_1;

    lcm
}

// TODO: seems like e must be at least 65537 according to the standard..
/// Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n))=1.
/// The search starts at `2^16 + 1 = 65537` and goes down
fn choose_e(lambda_n: &BoxedUint) -> BoxedUint {
    for i in (2..17u32).rev() {
        // actually one more, since 1 << n = 2^(n - 1)
        let mut e = BoxedUint::one_like(lambda_n);
        e.set_bit(i, Choice::TRUE);

        if &e >= lambda_n {
            continue;
        }

        if bool::from(lambda_n.gcd(&e).is_one()) {
            return e;
        }
    }

    unreachable!();
}

/// Generate the public and private keys. The key (i.e. modulus `n`) will have `key_size` bits.
pub fn generate_key(key_size: u64) -> RSAPrivateKey {
    //?  (1) Choose two large prime numbers p and q
    let (mut p, mut q) = generate_p_and_q(key_size);

    //?  (2) Compute n=pq
    let n = (p.as_ref() * q.as_ref()).into_odd().unwrap();

    //?  (3) Compute λ(n)
    let lambda_n = compute_lambda(&mut p, &mut q);

    //?  (4) Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n))=1
    let e = choose_e(&lambda_n);

    //?  (5) Determine d as `d ≡ e^(-1) (mod λ(n))`
    let d = e.invert_mod(&lambda_n.into_nz().unwrap()).unwrap();

    RSAPrivateKey::new(n, d, e, p, q)
}
