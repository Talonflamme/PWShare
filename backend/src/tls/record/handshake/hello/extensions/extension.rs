use crate::tls::record::alert::{Alert, Result};
use crate::tls::record::ciphers::cipher_suite::CipherConfig;
use crate::tls::record::hello::extensions::renegotiation_info::RenegotiationInfoExtension;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::{ReadableFromStream, Sink, WritableToSink};
use pwshare_macros::{IntoRepr, ReadableFromStream, WritableToSink};
use std::fmt::{Debug, Formatter};

#[repr(u16)]
#[derive(Debug, IntoRepr)]
pub enum ExtensionType {
    RenegotiationInfo(OpaqueExtensionData<RenegotiationInfoExtension>) = 65281,
    Unknown(OpaqueExtensionData<u8>) = 65535,
}

impl WritableToSink for ExtensionType {
    fn write(&self, buffer: &mut impl Sink<u8>, suite: Option<&CipherConfig>) -> Result<()> {
        if matches!(self, ExtensionType::Unknown(_)) {
            return Err(Alert::internal_error("Cannot write unknown ExtensionType"));
        }

        let repr: u16 = self.into();
        repr.write(buffer, suite)?;

        match self {
            ExtensionType::RenegotiationInfo(ri) => ri.write(buffer, suite)?,
            ExtensionType::Unknown(_) => unreachable!(),
        }

        Ok(())
    }
}

impl ReadableFromStream for ExtensionType {
    fn read(stream: &mut impl Iterator<Item = u8>, suite: Option<&CipherConfig>) -> Result<Self> {
        let repr = u16::read(stream, suite)?;

        Ok(match repr {
            65281 => Self::RenegotiationInfo(ReadableFromStream::read(stream, suite)?),
            _ => Self::Unknown(ReadableFromStream::read(stream, suite)?),
        })
    }
}

impl ExtensionType {
    pub fn new_renegotiation_info(rie: RenegotiationInfoExtension) -> Self {
        ExtensionType::RenegotiationInfo(vec![rie].into())
    }
}

#[derive(ReadableFromStream, WritableToSink)]
pub struct Extension {
    pub extension_type: ExtensionType,
}

/// Struct used to indicate that there is data after this, but it is not interpreted (e.g. because
/// it's not yet implemented).
pub type OpaqueExtensionData<T> = VariableLengthVec<T, 0, 65535>;

impl Debug for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Extension {:?}({})",
            self.extension_type,
            Into::<u16>::into(&self.extension_type)
        )
    }
}

/// Returns a list of extensions that are supported and are present in `client_extensions`.
///
/// `client_extensions`: The list of extensions from the `ClientHello` message.
pub fn filter_extensions(client_extensions: &Vec<Extension>) -> Vec<Extension> {
    Vec::new()
}
