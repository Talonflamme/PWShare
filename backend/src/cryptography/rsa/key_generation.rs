use super::lcm::{gcd, lcm};
use super::{rabin_miller::RabinMillerTest, PrivateKey, PublicKey, Sieve};
use crate::cryptography::rng::rng;
use crate::cryptography::rsa::private_key::AdditionalPrivateKeyInfo;
use crypto_bigint::{CheckedMul, InvMod, Random, RandomBits, Uint};


/// Generate a prime number with the specified amount of bits.
/// `L` is the capacity of the Uint type.
/// `num_bits` is the actual amount of bits that are randomized. Hence, the `num_bits` least significant
/// bits are randomized. This means that `num_bits` must be <= L * 64.
fn generate_prime<const L: usize>(num_bits: u32) -> Uint<L> {
    // the only case that this loop actually uses a second iteration is if there is no prime between the randomly
    // selected start and Uint::MAX. This has a chance of ~10^-307 and will never happen.

    loop {
        let start = Uint::<L>::random_bits(&mut rng!(), num_bits) | Uint::ONE; // make it odd

        // Instead of checking every or every 2 possible primes, we use a Sieve, similar to the Sieve of Eratosthenes algorithm.
        // So we only call `is_prime` on candidates that are not divisible by any of the first 2048 primes.
        let sieve = Sieve::new(start);

        for num in sieve {
            let bits = Uint::<L>::BITS - num.leading_zeros();

            if bits > num_bits {
                break; // we looked too far. The number exceeded the max of 2^(num_bits).
            }

            if is_prime(num) {
                return num;
            }
        }
    }
}

/// Checks if the given `candidate` is likely to be prime.
/// Chance of a false-positive is less than 10^-6
fn is_prime<const L: usize>(candidate: Uint<L>) -> bool {
    let rabin_miller = RabinMillerTest::new(candidate);
    rabin_miller.is_prime(None)
}

// Generates two primes of the given size.
fn generate_p_and_q<const L: usize>() -> (Uint<L>, Uint<L>) {
    // this amount of bits is half of the actual key (two primes are multiplied, two 1024 bit primes make a 1024² = 2048 bit key)
    let bits = (L * 64 / 2) as u32; // L * 64 = number of bits for value type, divide by 2 to get the private keys.
    let p = generate_prime(bits);
    let q = generate_prime(bits);

    (p, q)
}

/// Computes `λ(n)` with `n=pq` where λ is Carmichael's totient function. `p` and `q` are <i>assumed</i> to be prime.
/// Since `n=pq`, `λ(n) = lcm(λ(p), λ(q))` and since p and q are primes, `λ(p) = p - 1` and `λ(q) = q - 1`. Hence, `λ(n) = lcm(p - 1, q - 1)`.
fn compute_lambda<const L: usize>(p: &Uint<L>, q: &Uint<L>) -> Uint<L> {
    // applying that binary and operation resets the least significant bit. Since p and q are primes, that bit is initially 1.
    // setting it to 0 effectively subtracts one from the numbers.
    let lambda = lcm(p & !Uint::ONE, q & !Uint::ONE);

    lambda
}

/// Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n))=1.
/// The search starts at `2^16 + 1 = 65537` and goes down
fn choose_e<const L: usize>(lambda_n: &Uint<L>) -> Uint<L> {
    for i in (2..17usize).rev() {
        // actually one more, since 1 << n = 2^(n - 1)
        let e = Uint::ONE << i | Uint::ONE;

        if &e >= lambda_n {
            continue;
        }

        if gcd(*lambda_n, e) == Uint::ONE {
            return e; // e and λ(n) are co-prime
        }
    }

    // Should never come here
    // But we'll handle it anyways
    loop {
        let e = Uint::random(&mut rng!());

        if &e >= lambda_n {
            continue;
        }

        if gcd(e, *lambda_n) == Uint::ONE {
            return e;
        }
    }
}

macro_rules! generate_key {
    ($bits: expr) => {{
        const _ASSERT_DIV64: () = {
            if $bits % 64 != 0 {
                panic!("bits must be divisible by 64");
            }
        };

        $crate::rsa::key_generation::generate_keys::<{$bits / 64}>()
    }};
}

pub(crate) use generate_key;

/// Generate the public and private keys. Pr is the amount of Limbs for the private keys. Pu is the amount of Limbs for the public key.
/// `Pub = Pr * 2`. One Limb = 64 bits. The private keys (p and q), hence, will have a size of Pr * 64 bits.
/// The public key (product of p and q) uses double that amount, so Pr * 128 bits = Pu * 64 bits.
pub fn generate_keys<const L: usize>() -> (PublicKey<L>, PrivateKey<L>)
where
    Uint<L>: InvMod<Output = Uint<L>>,
{
    //?  (1) Choose two large prime numbers p and q
    let (p, q) = generate_p_and_q::<L>();

    //?  (2) Compute n=pq
    let n = p.checked_mul(&q).expect("overflow when multiplying");

    //?  (3) Compute λ(n)
    let lambda_n = compute_lambda(&p, &q);

    //?  (4) Choose an integer e such that 1 < e < λ(n) and gcd(e, λ(n))=1
    let e = choose_e(&lambda_n);

    //?  (5) Determine d as `d ≡ e^(-1) (mod λ(n))`
    let d = e.inv_mod(&lambda_n).unwrap();

    let pub_key = PublicKey::new(n, e);
    let prv_key = PrivateKey::new(n, d, AdditionalPrivateKeyInfo { e, p, q });

    (pub_key, prv_key)
}
