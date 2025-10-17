#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlgorithm {
    Null,
    Rsa,
    Ecdhe,
}