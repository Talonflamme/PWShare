use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::record::Handshake;
use crate::tls::{ReadableFromStream, WritableToSink};
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind, Read, Result};
use std::net::TcpStream;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, ReadableFromStream, WritableToSink)]
pub enum ContentType {
    ChangeCipherSpec = 20, // 0x14
    Alert = 21,            // 0x15
    Handshake = 22,        // 0x16
    ApplicationData = 23,  // 0x17
}

pub enum ContentTypeWithContent {
    ChangeCipherSpec(),
    Alert(),
    Handshake(Handshake),
    ApplicationData(),
}

impl Into<ContentType> for &ContentTypeWithContent {
    fn into(self) -> ContentType {
        match self {
            ContentTypeWithContent::ChangeCipherSpec() => ContentType::ChangeCipherSpec,
            ContentTypeWithContent::Alert() => ContentType::Alert,
            ContentTypeWithContent::Handshake(_) => ContentType::Handshake,
            ContentTypeWithContent::ApplicationData() => ContentType::ApplicationData,
        }
    }
}

#[derive(ReadableFromStream, WritableToSink)]
pub struct TLSPlaintext {
    content_type: ContentType,
    version: ProtocolVersion,
    // normally, here is a `length: u16` field, but that length is the length
    // for `fragment` and we simply use a VariableLengthVec as parsing is made
    // easier and the stored bytes are the same
    fragment: VariableLengthVec<u8, 0, 16384>, // 2^14
}

impl Debug for TLSPlaintext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, RecordHeader {{ length {:04x}, content-type: {:?} }}",
            self.version,
            self.fragment.len(),
            self.content_type
        )
    }
}

impl TLSPlaintext {
    pub fn read_from_stream(stream: &mut TcpStream) -> Result<Self> {
        // Header contains 5 bytes
        let mut header_buf = [0u8; 5];
        stream.read_exact(&mut header_buf)?;

        // last two of those bytes are length as u16 (big-endian)
        let length = (((header_buf[3] as u16) << 8) | header_buf[4] as u16) as usize;

        if length > 16384 {
            return Err(Error::new(ErrorKind::Other, format!("Length out of bounds: {}", length)));
        }

        let mut buf= vec![0; length];

        stream.read_exact(buf.as_mut_slice())?;

        let mut iter = header_buf.into_iter().chain(buf.into_iter());

        Self::read(&mut iter)
    }

    pub fn new(content: ContentTypeWithContent, version: ProtocolVersion) -> Result<Self> {
        let content_type = (&content).into();

        let mut bytes: Vec<u8> = Vec::new();

        match content {
            ContentTypeWithContent::ChangeCipherSpec() => {}
            ContentTypeWithContent::Alert() => {}
            ContentTypeWithContent::Handshake(h) => h.write(&mut bytes)?,
            ContentTypeWithContent::ApplicationData() => {}
        };

        let fragment: VariableLengthVec<u8, 0, 16384> = bytes.into();

        (&fragment).check_bounds()?;

        Ok(Self {
            content_type,
            version,
            fragment,
        })
    }

    pub fn get_content(self) -> Result<ContentTypeWithContent> {
        let mut iter = Into::<Vec<u8>>::into(self.fragment).into_iter();

        Ok(match self.content_type {
            ContentType::ChangeCipherSpec => ContentTypeWithContent::ChangeCipherSpec(),
            ContentType::Alert => ContentTypeWithContent::Alert(),
            ContentType::Handshake => ContentTypeWithContent::Handshake(Handshake::read(&mut iter)?),
            ContentType::ApplicationData => ContentTypeWithContent::ApplicationData()
        })
    }

    /// Returns a Handshake that parses the bytes of `self.fragment` if `self.content_type`
    /// is Handshake. Returns an `Err` otherwise.
    pub fn get_handshake(self) -> Result<Handshake> {
        if self.content_type != ContentType::Handshake {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Tried to read handshake, but header is for: {:?}",
                    self.content_type
                ),
            ));
        }

        let frag: Vec<u8> = self.fragment.into();
        let mut iter = frag.into_iter();

        Handshake::read(&mut iter)
    }
}
