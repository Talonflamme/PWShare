use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{Odd, Uint};
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub struct PublicKey<const L: usize> {
    pub n: Uint<L>,
    pub e: Uint<L>,
    n_montgomery: MontyParams<L>,
}

impl<const L: usize> PublicKey<L> {
    pub fn new(n: Uint<L>, e: Uint<L>) -> Self {
        let odd = Odd::new(n).unwrap();
        let params = MontyParams::new_vartime(odd);

        Self {
            n,
            e,
            n_montgomery: params,
        }
    }

    pub fn encode(&self, message_plain: Uint<L>) -> Uint<L> {
        assert!(self.n > message_plain, "Message representative out of range. m must be < n");
        
        let residue = MontyForm::new(&message_plain, self.n_montgomery).pow(&self.e);
        let cipher_text = residue.retrieve();
        cipher_text
    }
}

impl<const L: usize> Display for PublicKey<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.n, self.e)
    }
}

impl<const L: usize> PartialEq for PublicKey<L> {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.e == other.e
    }
}

impl<const L: usize> Eq for PublicKey<L> {}
