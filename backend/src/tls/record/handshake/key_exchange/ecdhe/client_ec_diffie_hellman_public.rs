use crate::tls::record::key_exchange::ecdhe::elliptic_curve::ECPoint;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, WritableToSink, ReadableFromStream)]
pub struct ClientECDiffieHellmanPublic {
    /// The client's ephemeral ECDH public key
    pub ecdh_yc: ECPoint,
}
