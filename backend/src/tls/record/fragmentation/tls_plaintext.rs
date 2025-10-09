use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::change_cipher_spec::ChangeCipherSpec;
use crate::tls::record::fragmentation::tls_compressed::TLSCompressed;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::record::Handshake;
use crate::tls::{ReadableFromStream, WritableToSink};
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::{Debug, Formatter};

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, ReadableFromStream, WritableToSink)]
pub enum ContentType {
    ChangeCipherSpec = 20, // 0x14
    Alert = 21,            // 0x15
    Handshake = 22,        // 0x16
    ApplicationData = 23,  // 0x17
}

pub enum ContentTypeWithContent {
    ChangeCipherSpec(ChangeCipherSpec),
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData(Vec<u8>),
}

impl Into<ContentType> for &ContentTypeWithContent {
    fn into(self) -> ContentType {
        match self {
            ContentTypeWithContent::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            ContentTypeWithContent::Alert(_) => ContentType::Alert,
            ContentTypeWithContent::Handshake(_) => ContentType::Handshake,
            ContentTypeWithContent::ApplicationData(_) => ContentType::ApplicationData,
        }
    }
}

pub struct TLSPlaintext {
    pub(crate) content_type: ContentType,
    pub(crate) version: ProtocolVersion,
    // normally, here is a `length: u16` field, but that length is the length
    // for `fragment` and we simply use a VariableLengthVec as parsing is made
    // easier and the stored bytes are the same
    pub(crate) fragment: VariableLengthVec<u8, 0, 16384>, // 2^14
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
    pub fn new(content: ContentTypeWithContent, version: ProtocolVersion) -> Result<Self> {
        let content_type = (&content).into();

        let mut bytes: Vec<u8> = Vec::new();

        match content {
            ContentTypeWithContent::Handshake(h) => h.write(&mut bytes)?,
            ContentTypeWithContent::ChangeCipherSpec(c) => c.write(&mut bytes)?,
            ContentTypeWithContent::Alert(a) => a.write(&mut bytes)?,
            ContentTypeWithContent::ApplicationData(mut b) => bytes.append(&mut b),
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
            ContentType::ChangeCipherSpec => {
                ContentTypeWithContent::ChangeCipherSpec(ChangeCipherSpec::read(&mut iter)?)
            }
            ContentType::Alert => ContentTypeWithContent::Alert(Alert::read(&mut iter)?),
            ContentType::Handshake => {
                ContentTypeWithContent::Handshake(Handshake::read(&mut iter)?)
            }
            ContentType::ApplicationData => ContentTypeWithContent::ApplicationData(iter.collect()),
        })
    }

    /// Returns a Handshake that parses the bytes of `self.fragment` if `self.content_type`
    /// is Handshake. Returns an `Err` otherwise.
    pub fn get_handshake(self) -> Result<Handshake> {
        if self.content_type != ContentType::Handshake {
            return Err(Alert::unexpected_message()); // expected handshake, got something other
        }

        let frag: Vec<u8> = self.fragment.into();
        let mut iter = frag.into_iter();

        let handshake = Handshake::read(&mut iter)?;

        if iter.next().is_some() {
            Err(Alert::decode_error()) // too many bytes
        } else {
            Ok(handshake)
        }
    }

    /// Returns a `ChangeCipherSpec` that is parsed from `self.fragment` if `self.content_type`
    /// is `ChangeCipherSpec`. Returns an `Err` otherwise.
    pub fn get_change_cipher_spec(self) -> Result<ChangeCipherSpec> {
        if self.content_type != ContentType::ChangeCipherSpec {
            return Err(Alert::unexpected_message()); // expected ChangeCipherSpec
        }

        let frag: Vec<u8> = self.fragment.into();
        let mut iter = frag.into_iter();

        let ccs = ChangeCipherSpec::read(&mut iter)?;

        if iter.next().is_some() {
            Err(Alert::decode_error())
        } else {
            Ok(ccs)
        }
    }

    /// Compresses the Plaintext into a `TLSCompressed` given the connection state.
    /// This function does the opposite of `TLSCompressed.decompress()`.
    pub fn compress(self, con_state: &ConnectionState) -> Result<TLSCompressed> {
        let compression = con_state.parameters.compression_algorithm()?;

        Ok(TLSCompressed {
            content_type: self.content_type,
            version: self.version,
            fragment: compression.compress(self.fragment)?,
        })
    }
}
