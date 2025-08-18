use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct Finished;

impl Finished {
    pub(super) fn new(bytes: &[u8]) -> Result<Self> {
        todo!()
    }
}
