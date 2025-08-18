use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ServerCertificate;

impl ServerCertificate {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
