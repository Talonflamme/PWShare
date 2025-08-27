use crate::tls::record::handshake::hello::extensions::signature_algorithms::SignatureAlgorithmsExtension;
use crate::tls::record::variable_length_vec::VariableLengthVec;
use pwshare_macros::{IntoRepr, ReadableFromStream};
use std::fmt::{Debug, Formatter};

#[repr(u16)]
#[derive(Debug, ReadableFromStream, IntoRepr)]
pub enum ExtensionType {
    ServerName(OpaqueExtensionData) = 0,
    ClientCertificateUrl(OpaqueExtensionData) = 2,
    TrustedCaKeys(OpaqueExtensionData) = 3,
    StatusRequest(OpaqueExtensionData) = 5,
    UserMapping(OpaqueExtensionData) = 6,
    SupportedGroups(OpaqueExtensionData) = 10,
    EcPointFormats(OpaqueExtensionData) = 11,
    SignatureAlgorithms(SignatureAlgorithmsExtension) = 13,
    UseSrtp(OpaqueExtensionData) = 14,
    Heartbeat(OpaqueExtensionData) = 15,
    ApplicationLayerProtocolNegotiation(OpaqueExtensionData) = 16,
    StatusRequestV2(OpaqueExtensionData) = 17,
    ClientCertificateType(OpaqueExtensionData) = 19,
    ServerCertificateType(OpaqueExtensionData) = 20,
    Padding(OpaqueExtensionData) = 21,
    EncryptThenMac(OpaqueExtensionData) = 22,
    ExtendedMainSecret(OpaqueExtensionData) = 23,
    TokenBinding(OpaqueExtensionData) = 24,
    CachedInfo(OpaqueExtensionData) = 25,
    CompressCertificate(OpaqueExtensionData) = 27,
    RecordSizeLimit(OpaqueExtensionData) = 28,
    DelegatedCredential(OpaqueExtensionData) = 34,
    SessionTicket(OpaqueExtensionData) = 35,
    SupportedEktCiphers(OpaqueExtensionData) = 39,
    PreSharedKey(OpaqueExtensionData) = 41,
    EarlyData(OpaqueExtensionData) = 42,
    SupportedVersions(OpaqueExtensionData) = 43,
    Cookie(OpaqueExtensionData) = 44,
    PskKeyExchangeModes(OpaqueExtensionData) = 45,
    CertificateAuthorities(OpaqueExtensionData) = 47,
    OidFilters(OpaqueExtensionData) = 48,
    PostHandshakeAuth(OpaqueExtensionData) = 49,
    SignatureAlgorithmsCert(OpaqueExtensionData) = 50,
    KeyShare(OpaqueExtensionData) = 51,
    TransparencyInfo(OpaqueExtensionData) = 52,
    ExternalIdHash(OpaqueExtensionData) = 55,
    ExternalSessionId(OpaqueExtensionData) = 56,
    QuicTransportParameters(OpaqueExtensionData) = 57,
    TicketRequest(OpaqueExtensionData) = 58,
    EchOuterExtensions(OpaqueExtensionData) = 64768,
    EncryptedClientHello(OpaqueExtensionData) = 65037,
    RenegotiationInfo(OpaqueExtensionData) = 65281,
    Unknown(OpaqueExtensionData) = 65535,
}

#[derive(ReadableFromStream)]
pub struct Extension {
    extension_type: ExtensionType,
}

/// Struct used to indicate that there is data after this, but it is not interpreted (e.g. because
/// it's not yet implemented).
#[derive(ReadableFromStream, Debug)]
pub struct OpaqueExtensionData {
    extension_data: VariableLengthVec<u8, 0, 65535>,
}

impl Debug for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let data: &dyn Debug = match &self.extension_type {
            ExtensionType::ServerName(a) => &a.extension_data,
            ExtensionType::ClientCertificateUrl(a) => &a.extension_data,
            ExtensionType::TrustedCaKeys(a) => &a.extension_data,
            ExtensionType::StatusRequest(a) => &a.extension_data,
            ExtensionType::UserMapping(a) => &a.extension_data,
            ExtensionType::SupportedGroups(a) => &a.extension_data,
            ExtensionType::EcPointFormats(a) => &a.extension_data,
            ExtensionType::SignatureAlgorithms(a) => &a.supported_signature_algorithms,
            ExtensionType::UseSrtp(a) => &a.extension_data,
            ExtensionType::Heartbeat(a) => &a.extension_data,
            ExtensionType::ApplicationLayerProtocolNegotiation(a) => &a.extension_data,
            ExtensionType::StatusRequestV2(a) => &a.extension_data,
            ExtensionType::ClientCertificateType(a) => &a.extension_data,
            ExtensionType::ServerCertificateType(a) => &a.extension_data,
            ExtensionType::Padding(a) => &a.extension_data,
            ExtensionType::EncryptThenMac(a) => &a.extension_data,
            ExtensionType::ExtendedMainSecret(a) => &a.extension_data,
            ExtensionType::TokenBinding(a) => &a.extension_data,
            ExtensionType::CachedInfo(a) => &a.extension_data,
            ExtensionType::CompressCertificate(a) => &a.extension_data,
            ExtensionType::RecordSizeLimit(a) => &a.extension_data,
            ExtensionType::DelegatedCredential(a) => &a.extension_data,
            ExtensionType::SessionTicket(a) => &a.extension_data,
            ExtensionType::SupportedEktCiphers(a) => &a.extension_data,
            ExtensionType::PreSharedKey(a) => &a.extension_data,
            ExtensionType::EarlyData(a) => &a.extension_data,
            ExtensionType::SupportedVersions(a) => &a.extension_data,
            ExtensionType::Cookie(a) => &a.extension_data,
            ExtensionType::PskKeyExchangeModes(a) => &a.extension_data,
            ExtensionType::CertificateAuthorities(a) => &a.extension_data,
            ExtensionType::OidFilters(a) => &a.extension_data,
            ExtensionType::PostHandshakeAuth(a) => &a.extension_data,
            ExtensionType::SignatureAlgorithmsCert(a) => &a.extension_data,
            ExtensionType::KeyShare(a) => &a.extension_data,
            ExtensionType::TransparencyInfo(a) => &a.extension_data,
            ExtensionType::ExternalIdHash(a) => &a.extension_data,
            ExtensionType::ExternalSessionId(a) => &a.extension_data,
            ExtensionType::QuicTransportParameters(a) => &a.extension_data,
            ExtensionType::TicketRequest(a) => &a.extension_data,
            ExtensionType::EchOuterExtensions(a) => &a.extension_data,
            ExtensionType::EncryptedClientHello(a) => &a.extension_data,
            ExtensionType::RenegotiationInfo(a) => &a.extension_data,
            ExtensionType::Unknown(a) => &a.extension_data,
        };

        write!(
            f,
            "Extension {:?}({}) {{ {:?} }}",
            self.extension_type,
            Into::<u16>::into(&self.extension_type),
            data
        )
    }
}
