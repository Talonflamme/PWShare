use crate::cryptography::rng::rng;
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};

pub struct MillerRabinTest<'a> {
    candidate: &'a BigUint,
    /// candidate = 2^s * d + 1
    d: BigUint,
    /// candidate = 2^s * d + 1
    s: usize,
}

pub enum Primality {
    ProbablyPrime,
    Composite,
}

impl Primality {
    pub fn is_probably_prime(&self) -> bool {
        match self {
            Self::ProbablyPrime => true,
            Self::Composite => false,
        }
    }
}

impl<'a> MillerRabinTest<'a> {
    pub fn new(candidate: &'a mut BigUint) -> Self {
        if candidate.is_even() {
            panic!("RabinMillerTest on even number");
        }

        if candidate.is_one() {
            panic!("RabinMillerTest on `1`");
        }

        candidate.set_bit(0, false); // subtract 1, make it even

        // make candidate = 2^s * d + 1
        let s = candidate.trailing_zeros().unwrap() as usize;
        let d = &*(candidate) >> s;

        candidate.set_bit(0, true); // make it the original again

        Self { candidate, s, d }
    }

    /// Determines if self.candidate is a (probable) prime.
    ///
    /// k defines the number of rounds, the RabinMiller test is ran. If it is None, the default value of 10 is used,
    /// reducing the chance of a false-positive to under 1 in a million. This chance is calculated by:
    ///
    /// Each iteration has a success chance of 3/4
    /// Hence, the chance for a false-positive after k rounds is (1/4)^k
    pub fn is_prime(&self, k: Option<usize>) -> bool {
        if self.candidate.is_one() || self.candidate.is_zero() {
            return false; // 1 and 0
        }

        let three = BigUint::from(3u8);

        if self.candidate <= &three {
            return true; // 2 and 3
        }

        if self.candidate.is_even() {
            return false;
        }

        let k = k.unwrap_or(10);

        assert!(k > 0, "k must be at least 1");
        let candidate_minus_one = self.candidate - &BigUint::one();

        // first, test a=2
        if !self
            .test_once(&BigUint::from(2u8), &candidate_minus_one)
            .is_probably_prime()
        {
            return false;
        }

        // start at 1, since we already checked for 2
        for _ in 1..k {
            // select random value from [3, candidate - 1)
            // we have already tested 2 and the cases 1 and candidate - 1 don't make sense.

            let a = rng!().gen_biguint_range(&three, &candidate_minus_one);

            if !self.test_once(&a, &candidate_minus_one).is_probably_prime() {
                return false;
            }
        }

        true
    }

    /// Do one iteration of the RabinMiller Test using the number a.
    /// Assumes a < candidate
    pub fn test_once(&self, a: &BigUint, candidate_minus_one: &BigUint) -> Primality {
        debug_assert!(a < &self.candidate, "a must be < candidate");

        let mut rem = a.modpow(&self.d, &self.candidate);

        if rem.is_one() || &rem == candidate_minus_one {
            return Primality::ProbablyPrime;
        }

        let two = BigUint::from(2u8);

        for _ in 1..self.s {
            rem = rem.modpow(&two, &self.candidate);

            if rem.is_one() {
                return Primality::Composite;
            } else if &rem == candidate_minus_one {
                return Primality::ProbablyPrime;
            }
        }

        Primality::Composite
    }
}
