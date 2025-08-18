use std::io::{Read, Result};
use std::net::{TcpListener, TcpStream};
use crate::tls::record::{Handshake, RecordHeader};

// TODO: eventually, we need to separate errors from IO and errors in the bytes supplied, in which
//  case we would send back an Error. Actually, we might even send it regardless.
fn handle_client(mut stream: TcpStream) -> Result<()> {
    println!("Got stream from: {}", stream.peer_addr()?);

    let header = RecordHeader::read_from_stream(&mut stream)?;
    let handshake = header.read_handshake_from_stream(&mut stream)?;

    println!("{:?}", header);
    println!("{:?}", handshake);

    Ok(())
}

// Command to do a TLS handshake: openssl s_client -connect 127.0.0.1:4981 -tls1_2 -servername localhost -msg -state -cipher AES128-SHA256
pub fn start_server() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4981")?;

    for stream in listener.incoming() {
        handle_client(stream?)?;
    }

    Ok(())
}
