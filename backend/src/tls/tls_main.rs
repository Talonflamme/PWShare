use crate::tls::record::compression_method::CompressionMethod;
use crate::tls::record::extensions;
use crate::tls::record::protocol_version::ProtocolVersion;
use crate::tls::record::{cipher_suite, ClientHello, Handshake, HandshakeType, Random, RecordFragment, RecordHeader, ServerHello, SessionID};
use crate::tls::{ReadableFromStream, WritableToSink};
use std::io::Result;
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
    let extensions = extensions::filter_extensions(&client_hello.extensions);

    let s = ServerHello {
        server_version: ProtocolVersion::tls1_2(),
        random: Random::generate(),
        cipher_suite,
        session_id: SessionID::new_empty(), // we do not store connections, so this is empty
        compression_method: CompressionMethod::Null, // no compression
        extensions: extensions.into()
    };

    // send_fragment(stream, &s)?;

    let mut buffer: Vec<u8> = Vec::new();
    s.write(&mut buffer).unwrap();

    println!("{:02x?}", buffer);

    let server_hello = ServerHello::read(&mut buffer.into_iter()).unwrap();
    println!("{:?}", server_hello);

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

fn send_fragment(stream: &mut TcpStream, record_fragment: &impl RecordFragment) -> Result<()> {
    todo!()
}

// Command to do a TLS handshake: openssl s_client -connect 127.0.0.1:4981 -tls1_2 -servername localhost -state -cipher AES128-SHA256 -trace -debug
pub fn start_server() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4981")?;

    for stream in listener.incoming() {
        handle_client(stream?)?;
    }

    Ok(())
}
