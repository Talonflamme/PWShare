use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ServerKeyExchange;

impl ServerKeyExchange {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
