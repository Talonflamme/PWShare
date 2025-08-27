use pwshare_macros::ReadableFromStream;
use crate::tls::record::cipher_suite::CipherSuite;
use crate::tls::record::compression_method::CompressionMethod;
use crate::tls::record::handshake::hello::{Extension, SessionID};
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::Random;
use crate::tls::record::variable_length_vec::VariableLengthVec;

#[derive(Debug, ReadableFromStream)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_method: CompressionMethod,
    pub extensions: VariableLengthVec<Extension, 0, 65335>
}
