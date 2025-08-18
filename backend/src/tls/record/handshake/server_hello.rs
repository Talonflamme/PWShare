use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ServerHello;

impl ServerHello {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
