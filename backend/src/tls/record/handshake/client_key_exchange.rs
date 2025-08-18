use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ClientKeyExchange;

impl ClientKeyExchange {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
