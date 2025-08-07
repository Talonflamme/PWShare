use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{CheckedAdd, Integer, NonZero, Odd, RandomMod, Uint};
use crate::cryptography::rng::rng;

pub struct RabinMillerTest<const L: usize> {
    candidate: Uint<L>,
    montgomery_terms: MontyParams<L>,
    /// candidate = 2^s * d + 1
    d: Uint<L>,
    /// candidate = 2^s * d + 1
    s: usize,
    one: MontyForm<L>,
    minus_one: MontyForm<L>,
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

impl<const L: usize> RabinMillerTest<L> {
    pub fn new(candidate: Uint<L>) -> Self {
        let odd = Odd::new(candidate).unwrap();
        let params = MontyParams::new_vartime(odd);

        let candidate_1 = candidate.wrapping_sub(&Uint::ONE);
        // make candidate = 2^s * d + 1
        let s = candidate_1.trailing_zeros() as usize;
        let d = candidate_1 >> s;
        let one = MontyForm::one(params);

        RabinMillerTest {
            candidate,
            montgomery_terms: params,
            s,
            d,
            minus_one: -one,
            one,
        }
    }

    /// Determines if self.candidate is a (probable) prime.
    ///
    /// k defines the number of rounds, the RabinMiller test is ran. If it is None, the default value of 10 is used,
    /// reducing the chance of a false-positive to under 1 in a million. This chance is calculated by:
    ///
    /// Each iteration has a success chance of 3/4
    /// Hence, the chance for a false-positive after k rounds is (1/4)^k
    pub fn is_prime(&self, k: Option<usize>) -> bool {
        if &self.candidate <= &Uint::ONE {
            return false; // 1 and 0
        } else if &self.candidate <= &Uint::from(3u8) {
            return true; // 2 and 3
        } else if self.candidate.is_even().into() {
            return false;
        }

        let k = k.unwrap_or(10);

        assert!(k > 0, "k must be at least 1");

        // first, test 2
        if !self.test_once(&Uint::from(2u8)).is_probably_prime() {
            return false;
        }

        // start at 1, since we already checked for 2
        for _ in 1..k {
            // select random value from [3, candidate - 1)
            // we have already tested 2 and the cases 1 and candidate - 1 don't make sense.
            let range_size = self.candidate.wrapping_sub(&Uint::from(4u8));
            let range_non_zero = NonZero::new(range_size).unwrap();

            let a = Uint::random_mod(&mut rng!(), &range_non_zero)
                .checked_add(&Uint::from(3u8))
                .expect("Integer overflow");

            if !self.test_once(&a).is_probably_prime() {
                return false;
            }
        }

        true
    }

    /// Do one iteration of the RabinMiller Test using the number a.
    /// Assumes a < candidate
    pub fn test_once(&self, a: &Uint<L>) -> Primality {
        debug_assert!(a < &self.candidate, "a must be < candidate");

        let residue = MontyForm::new(a, self.montgomery_terms);

        let mut rem = residue.pow(&self.d);

        if rem == self.one || rem == self.minus_one {
            return Primality::ProbablyPrime;
        }

        for _ in 1..self.s {
            rem = rem.square();
            if rem == self.one {
                return Primality::Composite;
            } else if rem == self.minus_one {
                return Primality::ProbablyPrime;
            }
        }

        Primality::Composite
    }
}
