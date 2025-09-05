use crate::tls::record::extensions::renegotiation_info::RenegotiationInfoExtension;
use crate::tls::record::handshake::hello::extensions::signature_algorithms::SignatureAlgorithmsExtension;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use crate::tls::{ReadableFromStream, WritableToSink};
use pwshare_macros::{IntoRepr, ReadableFromStream, WritableToSink};
use std::fmt::{Debug, Formatter};

#[repr(u16)]
#[derive(Debug, ReadableFromStream, WritableToSink, IntoRepr)]
pub enum ExtensionType {
    ServerName(OpaqueExtensionData<u8>) = 0,
    ClientCertificateUrl(OpaqueExtensionData<u8>) = 2,
    TrustedCaKeys(OpaqueExtensionData<u8>) = 3,
    StatusRequest(OpaqueExtensionData<u8>) = 5,
    UserMapping(OpaqueExtensionData<u8>) = 6,
    SupportedGroups(OpaqueExtensionData<u8>) = 10,
    EcPointFormats(OpaqueExtensionData<u8>) = 11,
    SignatureAlgorithms(SignatureAlgorithmsExtension) = 13,
    UseSrtp(OpaqueExtensionData<u8>) = 14,
    Heartbeat(OpaqueExtensionData<u8>) = 15,
    ApplicationLayerProtocolNegotiation(OpaqueExtensionData<u8>) = 16,
    StatusRequestV2(OpaqueExtensionData<u8>) = 17,
    ClientCertificateType(OpaqueExtensionData<u8>) = 19,
    ServerCertificateType(OpaqueExtensionData<u8>) = 20,
    Padding(OpaqueExtensionData<u8>) = 21,
    EncryptThenMac(OpaqueExtensionData<u8>) = 22,
    ExtendedMainSecret(OpaqueExtensionData<u8>) = 23,
    TokenBinding(OpaqueExtensionData<u8>) = 24,
    CachedInfo(OpaqueExtensionData<u8>) = 25,
    CompressCertificate(OpaqueExtensionData<u8>) = 27,
    RecordSizeLimit(OpaqueExtensionData<u8>) = 28,
    DelegatedCredential(OpaqueExtensionData<u8>) = 34,
    SessionTicket(OpaqueExtensionData<u8>) = 35,
    SupportedEktCiphers(OpaqueExtensionData<u8>) = 39,
    PreSharedKey(OpaqueExtensionData<u8>) = 41,
    EarlyData(OpaqueExtensionData<u8>) = 42,
    SupportedVersions(OpaqueExtensionData<u8>) = 43,
    Cookie(OpaqueExtensionData<u8>) = 44,
    PskKeyExchangeModes(OpaqueExtensionData<u8>) = 45,
    CertificateAuthorities(OpaqueExtensionData<u8>) = 47,
    OidFilters(OpaqueExtensionData<u8>) = 48,
    PostHandshakeAuth(OpaqueExtensionData<u8>) = 49,
    SignatureAlgorithmsCert(OpaqueExtensionData<u8>) = 50,
    KeyShare(OpaqueExtensionData<u8>) = 51,
    TransparencyInfo(OpaqueExtensionData<u8>) = 52,
    ExternalIdHash(OpaqueExtensionData<u8>) = 55,
    ExternalSessionId(OpaqueExtensionData<u8>) = 56,
    QuicTransportParameters(OpaqueExtensionData<u8>) = 57,
    TicketRequest(OpaqueExtensionData<u8>) = 58,
    EchOuterExtensions(OpaqueExtensionData<u8>) = 64768,
    EncryptedClientHello(OpaqueExtensionData<u8>) = 65037,
    RenegotiationInfo(OpaqueExtensionData<RenegotiationInfoExtension>) = 65281,
    Unknown(OpaqueExtensionData<u8>) = 65535,
}

impl ExtensionType {
    pub fn new_renegotiation_info(rie: RenegotiationInfoExtension) -> Self {
        ExtensionType::RenegotiationInfo(OpaqueExtensionData {
            extension_data: vec![rie].into(),
        })
    }
}

#[derive(ReadableFromStream, WritableToSink)]
pub struct Extension {
    pub extension_type: ExtensionType,
}

/// Struct used to indicate that there is data after this, but it is not interpreted (e.g. because
/// it's not yet implemented).
#[derive(ReadableFromStream, Debug, WritableToSink)]
pub struct OpaqueExtensionData<T>
where
    T: Debug + ReadableFromStream + WritableToSink,
{
    extension_data: VariableLengthVec<T, 0, 65535>,
}

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
