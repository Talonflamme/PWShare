use crate::cryptography::pem::FromPemContent;
use crate::cryptography::pkcs1_v1_5;
use crate::cryptography::rsa::PrivateKey;
use crate::tls::connection_state::compression_method::CompressionMethod;
use crate::tls::connection_state::connection_state::ConnectionState;
use crate::tls::connection_state::security_parameters::{ConnectionEnd, SecurityParameters};
use crate::tls::record::certificate::{ASN1Cert, Certificate};
use crate::tls::record::change_cipher_spec::ChangeCipherSpec;
use crate::tls::record::ciphers::cipher_suite;
use crate::tls::record::fragmentation::tls_ciphertext::TLSCiphertext;
use crate::tls::record::fragmentation::tls_plaintext::{ContentTypeWithContent, TLSPlaintext};
use crate::tls::record::hello::extensions::{Extension, ExtensionType, RenegotiationInfoExtension};
use crate::tls::record::hello::ServerHelloDone;
use crate::tls::record::hello::{extensions, ClientHello, ServerHello, SessionID};
use crate::tls::record::key_exchange::rsa::PreMasterSecret;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::{ClientKeyExchange, Finished, Handshake, HandshakeType, Random};
use std::fs;
use std::io::{Error, ErrorKind, Result, Write};
use std::net::TcpStream;

pub(crate) struct ConnectionStates {
    pub(crate) current_read: ConnectionState,
    pub(crate) current_write: ConnectionState,
    /// The security parameters of the pending write/read states. The `entity` field must
    /// be newly assigned when the pending states become the current states.
    pub(crate) pending_parameters: SecurityParameters,
}

impl ConnectionStates {
    fn activate_pending(&mut self, entity: ConnectionEnd) -> Result<ConnectionState> {
        let mut param = self.pending_parameters.clone();
        param.entity = Some(entity);
        Ok(ConnectionState::new(param)?)
    }

    fn activate_pending_read(&mut self) -> Result<()> {
        let read = self.activate_pending(ConnectionEnd::Client)?;
        self.current_read = read;
        Ok(())
    }

    fn activate_pending_write(&mut self) -> Result<()> {
        let write = self.activate_pending(ConnectionEnd::Server)?;
        self.current_write = write;
        Ok(())
    }

    fn reset_pending(&mut self) {
        self.pending_parameters = SecurityParameters::new_empty();
    }
}

/// The `Connection` struct holds information about a single connection to a single
/// client. This struct is responsible for negotiating the parameters (handshake) and
/// sending & encrypting, receiving & decrypting messages to & from the client.
pub struct Connection {
    /// The stream from which to read bytes and to which to write bytes to.
    pub(crate) stream: TcpStream,
    /// The current/pending read/write states
    pub(crate) connection_states: ConnectionStates,
    /// All handshake messages concatenated. This does not include HelloRequest and the next message
    /// (Finished) but all others in order.
    handshake_messages: Vec<u8>,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        let states = ConnectionStates {
            current_read: ConnectionState::create_no_encryption(ConnectionEnd::Client),
            current_write: ConnectionState::create_no_encryption(ConnectionEnd::Server),
            pending_parameters: SecurityParameters::new_empty(),
        };

        Connection {
            stream,
            connection_states: states,
            handshake_messages: Vec::new(),
        }
    }

    fn read_change_cipher_spec(&mut self) -> Result<ChangeCipherSpec> {
        let ciphertext = TLSCiphertext::read_from_connection(self)?;
        let compressed = ciphertext.decrypt(&self.connection_states.current_read)?;
        let plaintext = compressed.decompress(&self.connection_states.current_read)?;

        let ccs = plaintext.get_change_cipher_spec()?;
        Ok(ccs)
    }

    /// Returns the parsed Handshake and the bytes of the handshake message as a raw
    /// `Vec<u8>`.
    fn read_handshake(&mut self) -> Result<(Handshake, Vec<u8>)> {
        let ciphertext = TLSCiphertext::read_from_connection(self)?;
        let compressed = ciphertext.decrypt(&self.connection_states.current_read)?;
        let plaintext = compressed.decompress(&self.connection_states.current_read)?;

        let bytes = plaintext.fragment.clone();

        let handshake = plaintext.get_handshake()?;

        Ok((handshake, bytes))
    }

    fn read_client_hello(&mut self) -> Result<(ClientHello, Vec<u8>)> {
        let (handshake, bytes) = self.read_handshake()?;

        if let HandshakeType::ClientHello(ch) = handshake.msg_type {
            Ok((ch, bytes))
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "Expected ClientHello"))
        }
    }

    fn read_client_key_exchange(&mut self) -> Result<(ClientKeyExchange, Vec<u8>)> {
        let (handshake, bytes) = self.read_handshake()?;

        if let HandshakeType::ClientKeyExchange(cke) = handshake.msg_type {
            Ok((cke, bytes))
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Expected ClientKeyExchange",
            ))
        }
    }

    fn read_finished(&mut self) -> Result<(Finished, Vec<u8>)> {
        let (handshake, bytes) = self.read_handshake()?;

        if let HandshakeType::Finished(f) = handshake.msg_type {
            Ok((f, bytes))
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "Expected Finished"))
        }
    }

    fn send_server_hello(&mut self, client_hello: &ClientHello) -> Result<Vec<u8>> {
        let cipher_suite = cipher_suite::select_cipher_suite(&client_hello.cipher_suites).unwrap();
        let mut extensions = extensions::filter_extensions(&client_hello.extensions);

        cipher_suite.set_security_params(&mut self.connection_states.pending_parameters);

        extensions.push(Extension {
            extension_type: ExtensionType::new_renegotiation_info(RenegotiationInfoExtension {
                renegotiated_connection: Vec::new().into(),
            }),
        });

        let server_hello = ServerHello {
            server_version: ProtocolVersion::tls1_2(),
            random: Random::generate(),
            cipher_suite,
            session_id: SessionID::new_empty(), // we do not store connections, so this is empty
            compression_method: CompressionMethod::Null, // no compression
            extensions: extensions.into(),
        };

        self.connection_states
            .pending_parameters
            .compression_algorithm = Some(server_hello.compression_method.clone());

        self.connection_states.pending_parameters.client_random =
            Some(client_hello.random.to_bytes());

        self.connection_states.pending_parameters.server_random =
            Some(server_hello.random.to_bytes());

        let handshake = Handshake::new(HandshakeType::ServerHello(server_hello));
        self.send_fragment(ContentTypeWithContent::Handshake(handshake))
    }

    fn send_certificate(&mut self) -> Result<Vec<u8>> {
        let asn1cert = ASN1Cert::from_file("cert.pem")?;

        let certificate = Certificate {
            certificate_list: vec![asn1cert].into(),
        };

        let handshake = Handshake::new(HandshakeType::Certificate(certificate));
        self.send_fragment(ContentTypeWithContent::Handshake(handshake))
    }

    fn send_server_hello_done(&mut self) -> Result<Vec<u8>> {
        let server_hello_done = ServerHelloDone {};

        let handshake = Handshake::new(HandshakeType::ServerHelloDone(server_hello_done));
        self.send_fragment(ContentTypeWithContent::Handshake(handshake))
    }

    /// Responds to the ClientHello Message by sending a ServerHello, Certificate and ServerHelloDone
    /// message while also adjusting the pending SecurityParameters. Also adds the bytes of the
    /// handshake layer to `self.handshake_messages`.
    fn respond_to_client_hello(&mut self, client_hello: &ClientHello) -> Result<()> {
        let mut bytes = self.send_server_hello(client_hello)?;
        self.handshake_messages.append(&mut bytes);

        bytes = self.send_certificate()?;
        self.handshake_messages.append(&mut bytes);

        bytes = self.send_server_hello_done()?;
        self.handshake_messages.append(&mut bytes);

        Ok(())
    }

    fn send_change_cipher_spec(&mut self) -> Result<Vec<u8>> {
        let change_cipher_spec = ChangeCipherSpec::ChangeCipherSpec;
        self.send_fragment(ContentTypeWithContent::ChangeCipherSpec(change_cipher_spec))
    }

    fn send_finished(&mut self) -> Result<Vec<u8>> {
        let verify_data = Finished::calculate_verify_data(
            &self.connection_states.current_write,
            &self.handshake_messages,
        )?;

        let finished = Finished::new(verify_data);
        let handshake = Handshake::new(HandshakeType::Finished(finished));
        self.send_fragment(ContentTypeWithContent::Handshake(handshake))
    }

    /// Sends the `content`, adds a header and encrypts the message. Returns the bytes of the
    /// handshake message (without header).
    fn send_fragment(&mut self, content: ContentTypeWithContent) -> Result<Vec<u8>> {
        let tls_plaintext = TLSPlaintext::new(content, ProtocolVersion::tls1_2())?;

        let handshake_bytes = tls_plaintext.fragment.clone();

        let tls_compressed = tls_plaintext.compress(&self.connection_states.current_write)?;
        let tls_ciphertext = tls_compressed.encrypt(&self.connection_states.current_write)?;

        let mut bytes: Vec<u8> = Vec::new();
        tls_ciphertext.write(&mut bytes)?;

        self.stream.write_all(bytes.as_slice())?;

        Ok(handshake_bytes)
    }

    fn decode_pre_master_secret(
        &mut self,
        client_key_exchange: ClientKeyExchange,
    ) -> Result<PreMasterSecret> {
        let key_content = fs::read_to_string("private_key.pem")?;
        let key = PrivateKey::from_pem_content(key_content)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        client_key_exchange
            .exchange_keys
            .pre_master_secret
            .decrypt(move |bytes| {
                let padded = key.decrypt_bytes(bytes.as_slice()).map_err(|e| {
                    Error::new(ErrorKind::Other, format!("Decryption failed: {:?}", e))
                })?;

                let message = pkcs1_v1_5::unpad(&padded, key.size_in_bytes()).map_err(|e| {
                    Error::new(ErrorKind::Other, format!("Unpadding failed: {:?}", e))
                })?;

                Ok(message)
            })
    }

    fn convert_pre_master_to_master(
        &mut self,
        pre_master_secret: PreMasterSecret,
    ) -> Result<[u8; 48]> {
        if let Some(prf_func) = self
            .connection_states
            .pending_parameters
            .prf_algorithm
            .as_ref()
        {
            Ok(pre_master_secret
                .convert_to_master(prf_func, &self.connection_states.pending_parameters))
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "Handshake failed. No PRF negotiated",
            ))
        }
    }

    pub fn start_handshake(&mut self) -> Result<()> {
        let (client_hello, mut client_hello_bytes) = self.read_client_hello()?;
        self.handshake_messages.append(&mut client_hello_bytes);

        // send ServerHello, Certificate, ServerHelloDone
        self.respond_to_client_hello(&client_hello)?;

        let (client_key_exchange, mut bytes) = self.read_client_key_exchange()?;
        self.handshake_messages.append(&mut bytes);

        let pre_master = self.decode_pre_master_secret(client_key_exchange)?;
        let master = self.convert_pre_master_to_master(pre_master)?;

        self.connection_states.pending_parameters.master_secret = Some(master);

        // ChangeCipherSpec is not included in `handshake_messages`
        self.read_change_cipher_spec()?;

        self.connection_states.activate_pending_read()?;

        let (finished, mut bytes) = self.read_finished()?;

        finished.verify(
            &self.connection_states.current_read,
            &self.handshake_messages,
        )?;

        self.handshake_messages.append(&mut bytes);

        self.send_change_cipher_spec()?;
        self.connection_states.activate_pending_write()?;
        self.connection_states.reset_pending();

        self.send_finished()?;

        Ok(())
    }
}
