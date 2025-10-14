use crate::cryptography::hashing::{HashFunction, Sha256, Sha384};
use crate::tls::connection_state::mac::hmac;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy)]
pub enum PRFAlgorithm {
    TlsPrfSha256,
    TlsPrfSha384,
}

/// Struct for implementing the `P_hash` function.
pub struct PHash {
    hash: Box<dyn HashFunction>,
    secret: Vec<u8>,
    seed: Vec<u8>,

    /// The index of the last computed value of `A()`
    a_index: usize,

    /// The last computed value of `A()`. This is (in theory) equal to `A(a_index)`.
    /// As `A(0) = seed`, if `a_index == 0`, this value will be `None` and `seed` should be
    /// used instead. This simply saves redundant copying of `seed`.
    a_value: Option<Vec<u8>>,

    /// A Queue (FIFO) that holds already computed bytes that can be returned when needed.
    /// The front element will always be popped.
    bytes_queue: VecDeque<u8>,
}

impl PHash {
    fn new(hash: Box<dyn HashFunction>, secret: Vec<u8>, seed: Vec<u8>) -> Self {
        Self {
            hash,
            secret,
            seed,
            a_index: 0,
            a_value: None,
            bytes_queue: VecDeque::new(),
        }
    }

    /// Calculates `A(a_index + 1)`, stores it in `a_value` and increments `a_index`.
    /// * `A(0) = seed`
    /// * `A(i) = HMAC_hash(secret, A(i - 1))`
    fn calculate_next_a(&mut self) {
        // if `None`, then a_index = 0 and we use seed instead, since `A(0) = seed`
        let m = self.a_value.as_ref().unwrap_or(&self.seed);

        let next_a = hmac(self.hash.as_ref(), self.secret.as_slice(), m);

        self.a_value = Some(next_a);
        self.a_index += 1;
    }
}

impl Iterator for PHash {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(byte) = self.bytes_queue.pop_front() {
            return Some(byte);
        }

        self.calculate_next_a();

        // temporarily add seed to A()
        self.a_value
            .as_mut()
            .unwrap()
            .extend_from_slice(self.seed.as_slice());

        let hmac = hmac(
            self.hash.as_ref(),
            &self.secret,
            self.a_value.as_ref().unwrap(),
        );

        assert_eq!(
            self.a_value.as_ref().unwrap().len(),
            self.hash.h_len() + self.seed.len()
        );

        // remove seed again
        self.a_value.as_mut().unwrap().truncate(self.hash.h_len());

        self.bytes_queue = hmac.into();
        self.bytes_queue.pop_front() // always Some
    }
}

impl PRFAlgorithm {
    pub fn get_hash(&self) -> Box<dyn HashFunction> {
        match self {
            PRFAlgorithm::TlsPrfSha256 => Box::new(Sha256),
            PRFAlgorithm::TlsPrfSha384 => Box::new(Sha384),
        }
    }

    pub fn prf(&self, secret: &[u8], label: &str, seed: &[u8]) -> PHash {
        if !label.is_ascii() {
            panic!("Label must be all ASCII");
        }

        let hash = self.get_hash();

        let mut label_plus_seed: Vec<u8> = Vec::with_capacity(label.len() + seed.len());
        label_plus_seed.extend_from_slice(label.as_bytes());
        label_plus_seed.extend_from_slice(seed);

        let p_hash = PHash::new(hash, secret.to_vec(), label_plus_seed);
        p_hash
    }
}
