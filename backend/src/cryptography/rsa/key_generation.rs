use super::{rabin_miller::MillerRabinTest, PrivateKey, PublicKey, Sieve};
use crate::cryptography::rng::rng;
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;

/// Generate a prime number with the specified amount of bits.
/// `L` is the capacity of the Uint type.
/// `num_bits` is the actual amount of bits that are randomized. Hence, the `num_bits` least significant
/// bits are randomized. This means that `num_bits` must be <= L * 64.
fn generate_prime(num_bits: u64) -> BigUint {
    // the only case that this loop actually uses a second iteration is if there is no prime between the randomly
    // selected start and Uint::MAX. This has a chance of ~10^-307 and will never happen.

    loop {
        let mut start: BigUint = rng!().gen_biguint(num_bits);
        start.set_bit(0, true); // make it odd

        // Instead of checking every or every 2 possible primes, we use a Sieve, similar to the Sieve of Eratosthenes algorithm.
        // So we only call `is_prime` on candidates that are not divisible by any of the first 2048 primes.
        let sieve = Sieve::new(start, num_bits);

        for mut num in sieve {
            let bits = num.bits();

            if bits > num_bits {
                break; // we looked too far. The number exceeded the max of 2^(num_bits).
            }

            if is_prime(&mut num) {
                return num;
            }
        }
    }
}

/// Checks if the given `candidate` is likely to be prime.
/// Chance of a false-positive is less than 10^-6
fn is_prime(candidate: &mut BigUint) -> bool {
    let rabin_miller = MillerRabinTest::new(candidate);
    rabin_miller.is_prime(None)
}

/// Generates two primes of the given size.
///
/// `key_size` - The amount of bits of the modulus n. The two primes will have up to half of
/// this amount of bits.
fn generate_p_and_q(key_size: u64) -> (BigUint, BigUint) {
    // this amount of bits is half of the actual key (two primes are multiplied, two 1024 bit primes make a 1024² = 2048 bit key)
    let bits = key_size / 2; // L * 64 = number of bits for value type, divide by 2 to get the private keys.
    let p = generate_prime(bits);
    let q = generate_prime(bits);

    (p, q)
}

/// Computes `λ(n)` with `n=pq` where λ is Carmichael's totient function. `p` and `q` are <i>assumed</i> to be prime.
/// Since `n=pq`, `λ(n) = lcm(λ(p), λ(q))` and since p and q are primes, `λ(p) = p - 1` and `λ(q) = q - 1`. Hence, `λ(n) = lcm(p - 1, q - 1)`.
fn compute_lambda(p: &mut BigUint, q: &mut BigUint) -> BigUint {
    // applying that binary and operation resets the least significant bit. Since p and q are primes, that bit is initially 1.
    // setting it to 0 effectively subtracts one from the numbers.
    p.set_bit(0, false);
    q.set_bit(0, false);

    let lambda = p.lcm(q);

    // since p and q were primes, the first bit was 1 and we set it again
    p.set_bit(0, true);
    q.set_bit(0, true);

    lambda
}

// TODO: seems like e must be at least 65537 according to the standard..
/// Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n))=1.
/// The search starts at `2^16 + 1 = 65537` and goes down
fn choose_e(lambda_n: &BigUint) -> BigUint {
    for i in (2..17u64).rev() {
        // actually one more, since 1 << n = 2^(n - 1)
        let mut e = BigUint::one();
        e.set_bit(i, true);

        if &e >= lambda_n {
            continue;
        }

        if lambda_n.gcd(&e).is_one() {
            return e;
        }
    }

    // Should never come here
    // But we'll handle it anyway
    let lbound = BigUint::from(2u8);

    loop {
        let e = rng!().gen_biguint_range(&lbound, lambda_n);

        if lambda_n.gcd(&e).is_one() {
            return e;
        }
    }
}

// TODO: do massive speed ups here
// TODO: only return private key, we don't need separate public.
//  maybe make a function like .public() that returns a reference to a public key which builds on private key
/// Generate the public and private keys. The key (i.e. modulus `n`) will have `key_size` bits.
pub fn generate_keys(key_size: u64) -> (PublicKey, PrivateKey) {
    //?  (1) Choose two large prime numbers p and q
    let (mut p, mut q) = generate_p_and_q(key_size);

    //?  (2) Compute n=pq
    let n = &p * &q;

    //?  (3) Compute λ(n)
    let lambda_n = compute_lambda(&mut p, &mut q);

    //?  (4) Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n))=1
    let e = choose_e(&lambda_n);

    //?  (5) Determine d as `d ≡ e^(-1) (mod λ(n))`
    let d = e.modinv(&lambda_n).unwrap();

    let pub_key = PublicKey::new(n.clone(), e.clone());
    let prv_key = PrivateKey::new(n, d, e, p, q);

    (pub_key, prv_key)
}
