use crate::tls::connection::Connection;
use crate::tls::record::alert::Alert;
use std::io::Error;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

#[derive(Debug)]
pub enum IOErrorOrTLSError {
    /// Some IOError occurred, such as failing to connect.
    #[allow(dead_code)] // .0 is only used for Debug
    IOError(Error),
    /// Some TLS Error was sent. This means this server sends an alert.
    #[allow(dead_code)] // .0 is only used for Debug
    TLSErrorSent(Alert),
    /// Some TLS Error was received. This means the peer sent an alert.
    TLSErrorReceived(Alert),
}

impl From<Error> for IOErrorOrTLSError {
    fn from(value: Error) -> Self {
        IOErrorOrTLSError::IOError(value)
    }
}

impl From<Alert> for IOErrorOrTLSError {
    fn from(value: Alert) -> Self {
        IOErrorOrTLSError::TLSErrorSent(value)
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
        match &err {
            IOErrorOrTLSError::TLSErrorReceived(alert) => {
                eprintln!("RECEIVED Alert: {:?}", alert);
            }
            IOErrorOrTLSError::TLSErrorSent(alert) => {
                eprintln!("SENT Alert: {:?}", alert);
                connection.send_alert(alert.clone())?
            }
            IOErrorOrTLSError::IOError(io_err) => eprintln!("IO Error: {}", io_err),
        }

        // stream is closed when 'connection.stream' is dropped, so after this
        return Err(err);
    }

    connection.send_app_data(b"Hello World!".to_vec())?;

    let received = connection.receive_app_data()?;
    println!("Received: {:?}", String::from_utf8_lossy(&received));

    println!("Closing stream for: {}", addr);
    Ok(())
}

fn handle_client_and_error(stream: TcpStream) {
    match handle_client(stream) {
        Err(_) => eprintln!("Handling client failed"),
        Ok(()) => {}
    }
}

// Command to do a TLS handshake: openssl s_client -connect 127.0.0.1:4981 -tls1_2 -servername localhost -state -cipher ECDHE-RSA-AES128-GCM-SHA256 -trace -debug
// Command to host server: proj && cd PWShare/backend && openssl s_server -key key.pem -cert cert.pem -accept 8443
pub fn start_server() -> Result<(), IOErrorOrTLSError> {
    let addr = "127.0.0.1:4981";
    let listener = TcpListener::bind(addr)?;

    println!("Started server... listening to {}", addr);

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
