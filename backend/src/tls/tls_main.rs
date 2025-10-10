use crate::tls::connection::Connection;
use crate::tls::record::alert::Alert;
use std::io::Error;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

#[derive(Debug)]
pub enum IOErrorOrTLSError {
    #[allow(dead_code)] // .0 is only used for Debug
    IOError(Error),
    #[allow(dead_code)] // .0 is only used for Debug
    TLSError(Alert),
}

impl From<Error> for IOErrorOrTLSError {
    fn from(value: Error) -> Self {
        IOErrorOrTLSError::IOError(value)
    }
}

impl From<Alert> for IOErrorOrTLSError {
    fn from(value: Alert) -> Self {
        IOErrorOrTLSError::TLSError(value)
    }
}

// TODO: eventually, we need to separate errors from IO and errors in the bytes supplied, in which
//  case we would send back an Error. Actually, we might even send it regardless.
fn handle_client(stream: TcpStream) -> Result<(), IOErrorOrTLSError> {
    let addr = stream.peer_addr()?;

    println!("Got stream from: {}", addr);

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let mut connection = Connection::new(stream);

    if let Err(err) = connection.start_handshake() {
        match err {
            IOErrorOrTLSError::TLSError(alert) => {
                eprintln!("Alert: {:?}", alert);
                connection.send_alert(alert)?
            }
            IOErrorOrTLSError::IOError(io_err) => eprintln!("IO Error: {}", io_err),
        }
    }

    connection.send_app_data(b"Hello World!".to_vec())?;

    let received = connection.receive_app_data()?;
    println!("Received: {:?}", String::from_utf8_lossy(&received));

    println!("Closing stream for: {}", addr);
    Ok(())
}

fn handle_client_and_error(stream: TcpStream) {
    match handle_client(stream) {
        Err(e) => eprintln!("Error handling client: {:?}", e),
        Ok(()) => {}
    }
}

// Command to do a TLS handshake: openssl s_client -connect 127.0.0.1:4981 -tls1_2 -servername localhost -state -cipher AES128-SHA256 -trace -debug
// Command to host server: proj && cd PWShare/backend && openssl s_server -key key.pem -cert cert.pem -accept 8443
pub fn start_server() -> Result<(), IOErrorOrTLSError> {
    let listener = TcpListener::bind("127.0.0.1:4981")?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| handle_client_and_error(stream));
            }
            Err(e) => eprintln!("connection failed: {}", e),
        }
    }

    Ok(())
}
