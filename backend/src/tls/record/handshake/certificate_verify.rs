use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct CertificateVerify;

impl CertificateVerify {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
