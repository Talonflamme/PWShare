use std::fmt::{Debug, Formatter};
use pwshare_macros::{ReadableFromStream, WritableToSink};
use crate::util::UintDisplay;

#[derive(ReadableFromStream, WritableToSink)]
pub struct Finished {
    verify_data: [u8; 12]
}

impl Debug for Finished {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Finished {{ verify_data: {} }}", (&self.verify_data[..]).hex())
    }
}
