use crate::tls::record::variable_length_vec::VariableLengthVec;
use pwshare_macros::ReadableFromStream;
use std::fmt::{Debug, Formatter};

#[repr(u16)]
#[derive(Debug, ReadableFromStream, Copy, Clone)]
pub enum ExtensionType {
    ServerName = 0,
    ClientCertificateUrl = 2,
    TrustedCaKeys = 3,
    StatusRequest = 5,
    UserMapping = 6,
    SupportedGroups = 10,
    EcPointFormats = 11,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    StatusRequestV2 = 17,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    EncryptThenMac = 22,
    ExtendedMainSecret = 23,
    TokenBinding = 24,
    CachedInfo = 25,
    CompressCertificate = 27,
    RecordSizeLimit = 28,
    DelegatedCredential = 34,
    SessionTicket = 35,
    SupportedEktCiphers = 39,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    TransparencyInfo = 52,
    ExternalIdHash = 55,
    ExternalSessionId = 56,
    QuicTransportParameters = 57,
    TicketRequest = 58,
    EchOuterExtensions = 64768,
    EncryptedClientHello = 65037,
    RenegotiationInfo = 65281,
}

#[derive(ReadableFromStream)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: VariableLengthVec<u8, 0, 65535>,
}

impl Debug for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Extension {:?}({}) {{ {} }}",
            self.extension_type,
            self.extension_type.clone() as u16,
            self.extension_data
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ") // bytes separated by " "
        )
    }
}
