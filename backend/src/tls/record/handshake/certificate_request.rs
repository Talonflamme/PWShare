use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct CertificateRequest;

impl CertificateRequest {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
