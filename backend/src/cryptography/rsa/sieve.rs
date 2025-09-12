use std::ops::Rem;
use super::precompute::{SmallPrimeType, NUM_SMALL_PRIMES, SMALL_PRIMES};
use num_bigint::BigUint;

/// Implementation of the Sieve of Eratosthenes algorithm.
/// Works by selecting a set of small prime numbers. Each multiple is marked as a trivial number.
/// The remaining ones are non-trivial numbers and (even though not safe) could be primes.
pub(super) struct Sieve {
    /// the last found non-trivial number
    current: BigUint,
    // this slice is updated each iteration. Each entry represents the last checked number (mod p)
    last_mod: [SmallPrimeType; NUM_SMALL_PRIMES],
    /// Max amount of bits
    bits: u64
}

impl Sieve {
    /// Creates a new Sieve starting at `start`.
    /// Note that `start` is <b>not</b> included in the iterator.
    /// `bits` - the max amount of bits for any BigUint returned by this.
    pub fn new(mut start: BigUint, bits: u64) -> Self {
        start.set_bit(0, true); // make sure it's odd

        let mut last_mod = [0; NUM_SMALL_PRIMES];

        // make each value the biggest multiple of the corresponding prime that is less/equal than start
        last_mod.iter_mut().enumerate().for_each(|(i, x)| {
            let rem = (&start).rem(SMALL_PRIMES[i]);
            *x = rem.try_into().unwrap();
        });

        Sieve {
            current: start,
            last_mod,
            bits
        }
    }

    /// Updates self.progress and returns true if the next number is non-trivial.
    /// The next number is determined via `increment`. The last number isn't directly stored,
    /// but the `new_number = last_number + increment` is a requirement. Won't work otherwise.
    fn update_progress(&mut self, increment: SmallPrimeType) -> bool {
        let mut trivial = false;

        for (m, small_prime) in self.last_mod.iter_mut().zip(SMALL_PRIMES) {
            let new_mod = *m + increment;

            if new_mod > small_prime {
                *m = new_mod % small_prime;
            } else if new_mod < small_prime {
                *m = new_mod; // saved one mod operation
            } else {
                // we hit the next number right on the nail, it is sure to be a multiple of SMALL_PRIMES[i]
                trivial = true;
                *m = 0;
            }
        }

        !trivial
    }
}

impl Iterator for Sieve {
    type Item = BigUint;

    fn next(&mut self) -> Option<Self::Item> {
        let increment: SmallPrimeType = 2; // how much we move current each iteration

        // we increment self.current until we find a value, that is not a multiple of any prime
        loop {
            let next = (&self.current) + &increment;

            if next.bits() > self.bits {
                return None;
            }

            let non_trivial = self.update_progress(increment);

            self.current = next;

            if non_trivial {
                return Some(self.current.clone());
            }
            // else: number is trivial (= composite; divisible by any of the first few primes)
        }
    }
}
