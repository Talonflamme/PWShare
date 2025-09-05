use crate::tls::record::compression_method::CompressionMethod;
use crate::tls::record::extensions::{
    Extension, ExtensionType, RenegotiationInfoExtension,
};
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::{
    cipher_suite, ClientHello, Handshake, HandshakeType, Random, RecordFragment, RecordHeader,
    ServerHello, SessionID,
};
use crate::tls::record::{extensions, ContentType};
use crate::tls::WritableToSink;
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

    println!("{:?}", header);
    println!("{:#?}", handshake);

    respond_to_handshake(&mut stream, &handshake)?;

    Ok(())
}

fn respond_to_client_hello(stream: &mut TcpStream, client_hello: &ClientHello) -> Result<()> {
    let cipher_suite = cipher_suite::select_cipher_suite(&client_hello.cipher_suites).unwrap();
    let mut extensions = extensions::filter_extensions(&client_hello.extensions);

    extensions.push(Extension {
        extension_type: ExtensionType::new_renegotiation_info(RenegotiationInfoExtension {
            renegotiated_connection: Vec::new().into(),
        }),
    });

    let s = ServerHello {
        server_version: ProtocolVersion::tls1_2(),
        random: Random::generate(),
        cipher_suite,
        session_id: SessionID::new_empty(), // we do not store connections, so this is empty
        compression_method: CompressionMethod::Null, // no compression
        extensions: extensions.into(),
    };

    let handshake = Handshake::new(HandshakeType::ServerHello(s));
    send_fragment(stream, &handshake, ContentType::Handshake)?;

    Ok(())
}

fn respond_to_handshake(stream: &mut TcpStream, handshake: &Handshake) -> Result<()> {
    match &handshake.msg_type {
        HandshakeType::HelloRequest(_) => {}
        HandshakeType::ClientHello(ch) => respond_to_client_hello(stream, ch)?,
        HandshakeType::ServerHello(_) => {}
        HandshakeType::Certificate(_) => {}
        HandshakeType::ServerKeyExchange(_) => {}
        HandshakeType::CertificateRequest(_) => {}
        HandshakeType::ServerHelloDone(_) => {}
        HandshakeType::CertificateVerify(_) => {}
        HandshakeType::ClientKeyExchange(_) => {}
        HandshakeType::Finished(_) => {}
    }

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

    println!(">>> {:02x?}", fragment_bytes); // TODO: length is 004?? `Message length parse error!`

    let mut bytes: Vec<u8> = Vec::with_capacity(size_of::<RecordHeader>());
    header.write(&mut bytes)?;

    bytes.append(&mut fragment_bytes);

    stream.write_all(bytes.as_slice())?;

    Ok(())
}

// Command to do a TLS handshake: openssl s_client -connect 127.0.0.1:4981 -tls1_2 -servername localhost -state -cipher AES128-SHA256 -trace -debug
// Command to host server: openssl s_server -key key.pem -cert cert.pem -accept 8443
pub fn start_server() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4981")?;

    for stream in listener.incoming() {
        handle_client(stream?)?;
    }

    Ok(())
}
