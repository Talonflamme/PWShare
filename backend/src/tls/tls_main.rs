use crate::cryptography::pem::FromPemContent;
use crate::cryptography::pkcs1_v1_5;
use crate::cryptography::rsa::PrivateKey;
use crate::tls::connection_state::security_parameters::{
    CompressionMethod, ConnectionEnd, SecurityParameters,
};
use crate::tls::record::certificate::{ASN1Cert, Certificate};
use crate::tls::record::hello::extensions::{
    self, Extension, ExtensionType, RenegotiationInfoExtension,
};
use crate::tls::record::hello::{ClientHello, ServerHello, ServerHelloDone, SessionID};
use crate::tls::record::key_exchange::rsa::PreMasterSecret;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::ContentType;
use crate::tls::record::{
    cipher_suite, ClientKeyExchange, Handshake, HandshakeType, Random, RecordFragment, RecordHeader,
};
use crate::tls::WritableToSink;
use crate::util::UintDisplay;
use num_bigint::BigUint;
use std::fs;
use std::io::{Error, ErrorKind, Result, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

// TODO: eventually, we need to separate errors from IO and errors in the bytes supplied, in which
//  case we would send back an Error. Actually, we might even send it regardless.
fn handle_client(mut stream: TcpStream) -> Result<()> {
    println!("Got stream from: {}", stream.peer_addr()?);

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let header = RecordHeader::read_from_stream(&mut stream)?;
    let handshake = header.read_handshake_from_stream(&mut stream)?;

    // should be ClientHello
    let HandshakeType::ClientHello(client_hello) = handshake.msg_type else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Expected ClientHello, got: {:?}", handshake.msg_type),
        ));
    };

    // TODO: check version and abort if less than TLS 1.2

    // respond
    respond_to_client_hello(&mut stream, &client_hello)?;

    let header = RecordHeader::read_from_stream(&mut stream)?;
    let handshake = header.read_handshake_from_stream(&mut stream)?;

    // no Certificate, since we did not request one
    // now we expect ClientKeyExchange
    let HandshakeType::ClientKeyExchange(client_key_exchange) = handshake.msg_type else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Expected ClientKeyExchange, got: {:?}", handshake.msg_type),
        ));
    };

    println!("{:?}", client_key_exchange);

    let pre_master = decode_pre_master_secret(client_key_exchange)?;

    println!("{:?}", pre_master);

    Ok(())
}

fn decode_pre_master_secret(client_key_exchange: ClientKeyExchange) -> Result<PreMasterSecret> {
    let key_content = fs::read_to_string("private_key.pem")?;
    let key = PrivateKey::from_pem_content(key_content)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    client_key_exchange
        .exchange_keys
        .pre_master_secret
        .decrypt(move |bytes| {
            let padded = key
                .decrypt_bytes(bytes.as_slice())
                .map_err(|e| Error::new(ErrorKind::Other, format!("Decryption failed: {:?}", e)))?;

            let message = pkcs1_v1_5::unpad(&padded, key.size_in_bytes())
                .map_err(|e| Error::new(ErrorKind::Other, format!("Unpadding failed: {:?}", e)))?;

            Ok(message)
        })
}

fn send_server_hello(
    stream: &mut TcpStream,
    client_hello: &ClientHello,
    params: &mut SecurityParameters,
) -> Result<()> {
    let cipher_suite = cipher_suite::select_cipher_suite(&client_hello.cipher_suites).unwrap();
    let mut extensions = extensions::filter_extensions(&client_hello.extensions);

    cipher_suite.set_security_params(params);

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

    params.compression_algorithm = Some(server_hello.compression_method.clone());
    params.client_random = Some(client_hello.random.to_bytes());
    params.server_random = Some(server_hello.random.to_bytes());

    let handshake = Handshake::new(HandshakeType::ServerHello(server_hello));
    send_fragment(stream, &handshake, ContentType::Handshake)?;
    Ok(())
}

fn send_certificate(stream: &mut TcpStream) -> Result<()> {
    let asn1cert = ASN1Cert::from_file("cert.pem")?;

    let certificate = Certificate {
        certificate_list: vec![asn1cert].into(),
    };

    let handshake = Handshake::new(HandshakeType::Certificate(certificate));
    send_fragment(stream, &handshake, ContentType::Handshake)?;

    Ok(())
}

fn send_server_hello_done(stream: &mut TcpStream) -> Result<()> {
    let server_hello_done = ServerHelloDone {};

    let handshake = Handshake::new(HandshakeType::ServerHelloDone(server_hello_done));
    send_fragment(stream, &handshake, ContentType::Handshake)?;

    Ok(())
}

fn respond_to_client_hello(stream: &mut TcpStream, client_hello: &ClientHello) -> Result<()> {
    let mut params = SecurityParameters::new_empty(ConnectionEnd::Server);

    send_server_hello(stream, client_hello, &mut params)?;
    send_certificate(stream)?;
    send_server_hello_done(stream)?;

    Ok(())
}

fn send_fragment(
    stream: &mut TcpStream,
    record_fragment: &impl RecordFragment,
    content_type: ContentType,
) -> Result<()> {
    let mut fragment_bytes = record_fragment.to_data()?;

    if fragment_bytes.len() > (1 << 14) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Length: {} must not exceed 2^14", fragment_bytes.len()),
        ));
    }

    let header = RecordHeader {
        content_type,
        version: ProtocolVersion::tls1_2(),
        length: fragment_bytes.len() as u16,
    };

    println!(">>> [{}]", fragment_bytes.hex_with_sep(" "));

    let mut bytes: Vec<u8> = Vec::with_capacity(size_of::<RecordHeader>());
    header.write(&mut bytes)?;

    bytes.append(&mut fragment_bytes);

    stream.write_all(bytes.as_slice())?;

    Ok(())
}

// Command to do a TLS handshake: openssl s_client -connect 127.0.0.1:4981 -tls1_2 -servername localhost -state -cipher AES128-SHA256 -trace -debug
// Command to host server: proj && cd PWShare/backend && openssl s_server -key key.pem -cert cert.pem -accept 8443
pub fn start_server() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4981")?;

    for stream in listener.incoming() {
        handle_client(stream?)?;
    }

    Ok(())
}
