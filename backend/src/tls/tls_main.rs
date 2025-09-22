use crate::tls::connection::Connection;
use std::io::Result;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

// TODO: eventually, we need to separate errors from IO and errors in the bytes supplied, in which
//  case we would send back an Error. Actually, we might even send it regardless.
fn handle_client(stream: TcpStream) -> Result<()> {
    println!("Got stream from: {}", stream.peer_addr()?);

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let mut connection = Connection::new(stream);

    connection.start_handshake()?;

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
