use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ClientHello;

impl ClientHello {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
