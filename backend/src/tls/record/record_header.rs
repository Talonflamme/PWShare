use super::protocol_version::ProtocolVersion;
use super::Handshake;
use crate::tls::ReadableFromStream;
use pwshare_macros::ReadableFromStream;
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::{ErrorKind, Read};
use std::net::TcpStream;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, ReadableFromStream)]
pub enum ContentType {
    ChangeCipherSpec = 20, // 0x14
    Alert = 21,            // 0x15
    Handshake = 22,        // 0x16
    ApplicationData = 23,  // 0x17
}

impl TryFrom<u8> for ContentType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            _ => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("Content Type: {:02x} unexpected", value),
            )),
        }
    }
}

#[derive(ReadableFromStream)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub version: ProtocolVersion,
    pub length: u16,
}

impl Debug for RecordHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, RecordHeader {{ length {:04x}, content-type: {:?} }}",
            self.version,
            self.length,
            self.content_type
        )
    }
}

impl RecordHeader {
    pub fn read_from_stream(stream: &mut TcpStream) -> io::Result<RecordHeader> {
        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf)?;
        let mut iter = buf.iter().take(n).copied();
        Self::read(&mut iter)
    }

    pub fn read_handshake_from_stream(&self, stream: &mut TcpStream) -> io::Result<Handshake> {
        if self.content_type != ContentType::Handshake {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Tried to read handshake, but header is for: {:?}",
                    self.content_type
                ),
            ));
        }

        // max length is 2^14 (= 16384)
        if self.length > 16384 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Cannot read handshake from stream as length specified in header is > 2^14: {}",
                    self.length
                ),
            ));
        }

        let mut buf = vec![0u8; self.length as usize];

        let n = stream.read(buf.as_mut_slice())?;

        Handshake::read_from_bytes(&buf[..n])
    }
}
