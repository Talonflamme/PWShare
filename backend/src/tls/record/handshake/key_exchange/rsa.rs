use crate::tls::connection_state::prf::PRFAlgorithm;
use crate::tls::connection_state::security_parameters::SecurityParameters;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::public_key_encrypted::PublicKeyEncrypted;
use crate::util::UintDisplay;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::fmt::{Debug, Formatter};

#[derive(Debug, ReadableFromStream, WritableToSink)]
pub struct EncryptedPreMasterSecret {
    pub pre_master_secret: PublicKeyEncrypted<PreMasterSecret>,
}

#[repr(C)]
#[derive(ReadableFromStream, WritableToSink)]
pub struct PreMasterSecret {
    client_version: ProtocolVersion,
    random: [u8; 46],
}

impl PreMasterSecret {
    pub fn convert_to_master(
        self,
        prf: &PRFAlgorithm,
        security_parameters: &SecurityParameters,
    ) -> [u8; 48] {
        let pre_master: [u8; 48] = self.into();

        let client_hello_random = security_parameters.client_random.as_ref().unwrap();
        let server_hello_random = security_parameters.server_random.as_ref().unwrap();

        let mut seed = Vec::with_capacity(client_hello_random.len() + server_hello_random.len());
        seed.extend_from_slice(client_hello_random);
        seed.extend_from_slice(server_hello_random);

        let phash = prf.prf(&pre_master, "master secret", seed.as_slice());

        phash.take(48).collect::<Vec<u8>>().try_into().expect("Not enough bytes for master secret")
    }
}

impl Into<[u8; 48]> for PreMasterSecret {
    fn into(self) -> [u8; 48] {
        //noinspection RsAssertEqual
        const _: () = assert!(size_of::<PreMasterSecret>() == 48);
        //noinspection RsAssertEqual
        const _: () = assert!(align_of::<PreMasterSecret>() == 1);

        let ptr: *const [u8; 48] = &self as *const PreMasterSecret as *const [u8; 48];
        // this is not actually unsafe as we checked above that the entire size of
        // PreMasterSecret is 48 and is tightly packed (alignment 1).
        unsafe { *ptr }
    }
}

impl Debug for PreMasterSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", UintDisplay::hex(&self.random.as_slice()))
    }
}
