use crypto_bigint::{BoxedUint, Integer, RandomMod};
use crypto_bigint::{Limb, Odd, One, Unsigned};

pub struct MillerRabinTest<'a> {
    candidate: &'a Odd<BoxedUint>,
    /// candidate = 2^s * d + 1
    d: BoxedUint,
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
    pub fn new(candidate: &'a mut Odd<BoxedUint>) -> Self {
        if bool::from(candidate.is_even()) {
            panic!("RabinMillerTest on even number");
        }

        if bool::from(candidate.is_one()) {
            panic!("RabinMillerTest on `1`");
        }

        let candidate_minus_1 = candidate.as_ref() - BoxedUint::one_like(candidate);

        // make candidate = 2^s * d + 1
        let s = candidate_minus_1.trailing_zeros() as usize;
        let d = candidate_minus_1.shr(s as u32);

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
        if bool::from(self.candidate.is_one()) || bool::from(self.candidate.is_zero()) {
            return false; // 1 and 0
        }

        let three = BoxedUint::from_limb_like(Limb(3), self.candidate);

        if self.candidate.as_ref() <= &three {
            return true; // 2 and 3
        }

        if bool::from(self.candidate.is_even()) {
            return false;
        }

        let k = k.unwrap_or(10);

        assert!(k > 0, "k must be at least 1");
        let candidate_minus_one = (self.candidate.as_ref() - BoxedUint::one_like(self.candidate))
            .into_nz()
            .unwrap();

        // first, test a=2
        if !self
            .test_once(
                &BoxedUint::from_limb_like(Limb(2), self.candidate),
                &candidate_minus_one,
            )
            .is_probably_prime()
        {
            return false;
        }

        let three = BoxedUint::from_limb_like(Limb(3), &candidate_minus_one);

        // start at 1, since we already checked for 2
        for _ in 1..k {
            // select random value from [3, candidate - 1)
            // we have already tested 2 and the cases 1 and candidate - 1 don't make sense.

            loop {
                let a = BoxedUint::random_mod_vartime(&mut rand::rng(), &candidate_minus_one);

                if a < three {
                    continue; // very unlikely, but still required
                }

                if !self.test_once(&a, &candidate_minus_one).is_probably_prime() {
                    return false;
                }
            }
        }

        true
    }

    /// Do one iteration of the RabinMiller Test using the number a.
    /// Assumes a < candidate
    pub fn test_once(&self, a: &BoxedUint, candidate_minus_one: &BoxedUint) -> Primality {
        debug_assert!(a < &self.candidate.as_ref(), "a must be < candidate");

        let mut rem = a.pow_mod(&self.d, self.candidate);

        if bool::from(rem.is_one()) || &rem == candidate_minus_one {
            return Primality::ProbablyPrime;
        }

        for _ in 1..self.s {
            rem = rem.square_mod(self.candidate.as_nz_ref());

            if rem.is_one().into() {
                return Primality::Composite;
            } else if &rem == candidate_minus_one {
                return Primality::ProbablyPrime;
            }
        }

        Primality::Composite
    }
}
