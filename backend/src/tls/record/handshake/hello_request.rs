use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
/// The Hello Request message is empty.
pub struct HelloRequest;

impl HelloRequest {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == 0 {
            Ok(HelloRequest)
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("HelloRequest expects 0 bytes, got {}", bytes.len()),
            ))
        }
    }
}
