use crypto_bigint::{CheckedAdd, Uint};

use super::precompute::{NUM_SMALL_PRIMES, SMALL_PRIMES, SmallPrimeType, RECIPROCALS};

/// Implementation of the Sieve of Eratosthenes algorithm.
/// Works by selecting a set of small prime numbers. Each multiple is marked as a trivial number.
/// The remaining ones are non-trivial numbers and (even though not safe) could be primes.
pub(super) struct Sieve<const L: usize> {
    /// the last found non-trivial number
    current: Uint<L>,
    // this slice is updated each iteration. Each entry represents the last checked number (mod p)
    last_mod: [SmallPrimeType; NUM_SMALL_PRIMES]
}

impl<const L: usize> Sieve<L> {
    /// Creates a new Sieve starting at `start`.
    /// Note that `start` is <b>not</b> included in the iterator.
    pub fn new(mut start: Uint<L>) -> Self {
        start |= Uint::ONE; // make sure it's odd

        let mut last_mod = [0; NUM_SMALL_PRIMES];

        // make each value the biggest multiple of the corresponding prime that is less/equal than start
        last_mod.iter_mut().enumerate().for_each(|(i, x)| {
            // let rem = start.rem(&prime);
            let rem = start.rem_limb_with_reciprocal(&RECIPROCALS[i]);
            *x = rem.0 as SmallPrimeType;
        });
        
        Sieve::<L> {
            current: start,
            last_mod
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

impl<const L: usize> Iterator for Sieve<L> {
    type Item = Uint<L>;

    fn next(&mut self) -> Option<Self::Item> {
        let increment: SmallPrimeType = 2; // how much we move current each iteration

        // we increment self.current until we find a value, that is not a multiple of any prime
        loop {
            if let Some(next) = self.current.checked_add(&Uint::from(increment)).into_option() {
                let non_trivial = self.update_progress(increment);

                self.current = next;

                if non_trivial {
                    return Some(self.current);
                }
                // else: number is trivial (= composite; divisible by any of the first few primes)
            } else {
                // overflow: we are done
                return None;
            }
        }
    }
}
