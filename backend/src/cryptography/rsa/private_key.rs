use std::fmt::{Debug, Display};

use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{Odd, Uint};

#[derive(Debug)]
pub struct PrivateKey<const L: usize> {
    pub n: Uint<L>,
    pub d: Uint<L>,
    pub add_info: AdditionalPrivateKeyInfo<L>,
    n_montgomery: MontyParams<L>,
}

#[derive(Debug)]
pub struct AdditionalPrivateKeyInfo<const L: usize> {
    pub e: Uint<L>,
    pub p: Uint<L>,
    pub q: Uint<L>
}

impl<const L: usize> PrivateKey<L> {
    pub fn new(n: Uint<L>, d: Uint<L>, add_info: AdditionalPrivateKeyInfo<L>) -> Self {
        let odd = Odd::new(n).unwrap();
        let params = MontyParams::new_vartime(odd);

        Self {
            n,
            d,
            add_info,
            n_montgomery: params,
        }
    }

    pub fn decode(&self, message_cipher: Uint<L>) -> Uint<L> {
        assert!(self.n > message_cipher, "ciphertext representative out of range");

        let residue = MontyForm::new(&message_cipher, self.n_montgomery).pow(&self.d);
        let message_plain = residue.retrieve();
        message_plain
    }
}

impl<const L: usize> Display for PrivateKey<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.n, self.d)
    }
}

impl<const L: usize> PartialEq for PrivateKey<L> {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.d == other.d
    }
}

impl<const L: usize> Eq for PrivateKey<L> {}
