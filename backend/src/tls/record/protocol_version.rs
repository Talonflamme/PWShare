use pwshare_macros::ReadableFromStream;
use std::fmt::{Debug, Display, Formatter};

#[derive(ReadableFromStream)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    #[inline]
    /// Returns a Protocol Version that is TLS1.2 (0x0303)
    pub fn tls1_2() -> ProtocolVersion {
        ProtocolVersion {
            major: 0x03,
            minor: 0x03
        }
    }
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

impl Debug for ProtocolVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}
