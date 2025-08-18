use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ServerHelloDone;

impl ServerHelloDone {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
