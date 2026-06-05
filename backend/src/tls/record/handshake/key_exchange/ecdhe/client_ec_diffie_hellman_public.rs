use crate::cryptography::elliptic_curves::ECDHPrivateKey;
use crate::tls::record::alert::{Alert, AlertResult};
use crate::tls::record::key_exchange::ecdhe::elliptic_curve::{ECPoint, NamedCurve};
use crate::tls::record::key_exchange::pre_master_secret::PreMasterSecret;
use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, WritableToSink, ReadableFromStream)]
pub struct ClientECDiffieHellmanPublic {
    /// The client's ephemeral ECDH public key
    pub ecdh_yc: ECPoint,
}

impl ClientECDiffieHellmanPublic {
    pub fn compute_pre_master(
        self,
        private_key: &ECDHPrivateKey,
        named_curve: NamedCurve,
    ) -> AlertResult<PreMasterSecret> {
        let curve = named_curve.curve()?;

        // For example with X25519:
        // x_peer = X25519(d_client, G) with d_client being the private key of the client
        let x_peer = self.ecdh_yc.to_point(named_curve)?;

        ECPoint::verify_weierstrass(x_peer.clone(), named_curve)?;

        // x_S = X25519(d_server, x_peer) with d_server being the private key of the server
        let shared_secret = curve.scalar_multiply(&private_key.key, x_peer);

        let secret = ECPoint::encode_x_coordinate(shared_secret.x, named_curve)?;

        // all zeros are not allowed, handshake must be aborted
        if secret.iter().copied().reduce(|a, b| a | b).unwrap() == 0 {
            Err(Alert::handshake_failure())
        } else {
            Ok(PreMasterSecret(secret))
        }
    }
}
