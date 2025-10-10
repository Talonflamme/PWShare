#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlgorithm {
    Null,
    DheDss,
    DheRsa,
    DhAnon,
    Rsa,
    DhDss,
    DhRsa
}