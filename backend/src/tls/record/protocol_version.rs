use std::fmt::{Display, Formatter};

pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8
}

impl Display for ProtocolVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.major != 3 || self.minor > 4 {
            write!(f, "Version {}.{}", self.major, self.minor)
        } else {
            write!(f, "TLS 1.{}", self.minor - 1)
        }
    }
}
