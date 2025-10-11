use crate::tls::connection::Connection;
use crate::tls::record::ciphers::cipher_suite::{CipherSuite, SUPPORTED_CIPHER_SUITES};
use pwshare_macros::generate_cipher_suite_tests;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

fn test_cipher_suite_handle_client(
    stream: TcpStream,
    message_to_send: String,
    message_to_receive: String,
) {
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_nonblocking(false)
        .expect("Could not set to blocking");

    let mut con = Connection::new(stream);
    con.start_handshake().unwrap();

    con.send_app_data(message_to_send.into_bytes()).unwrap();

    let recv = con.receive_app_data().unwrap();

    assert_eq!(message_to_receive.into_bytes(), recv);
}

fn test_cipher_suite(cipher_suite: CipherSuite, index: usize) {
    let port = 7810 + index;
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();

    listener
        .set_nonblocking(true)
        .expect("Cannot set to non-blocking");

    let message_to_send = format!("Hello world from server using: {:?}", cipher_suite);
    let message_to_receive = format!("Hello back from client using: {:?}", cipher_suite);

    // spawn client
    let current_file = Path::new(file!());
    let client_file = current_file.parent().unwrap().join("test_client.py");
    assert!(client_file.exists(), "Failed to resolve `test_client.py`");

    let cipher = cipher_suite as u16;

    let child = Command::new("python")
        .arg(client_file)
        .arg("--port")
        .arg(port.to_string())
        .arg("--cipher")
        .arg(format!("{:04X}", cipher))
        .arg("--expect")
        .arg(&message_to_send)
        .arg("--send")
        .arg(&message_to_receive)
        .arg("--delay")
        .arg("500") // 500ms
        .spawn()
        .expect("Failed to start Python script");

    let timeout = Duration::from_secs(5);
    let start = Instant::now();

    // this way, we can implement a timeout
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                test_cipher_suite_handle_client(stream, message_to_send, message_to_receive);
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() >= timeout {
                    panic!("Timed out waiting for TCP connection");
                }
                sleep(Duration::from_millis(50)); // avoid busy-waiting
            }
            Err(e) => panic!("Connecting failed: {:?}", e),
        }
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait on child process");

    if !output.stdout.is_empty() {
        println!(
            "Python stdout:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    if !output.stderr.is_empty() {
        eprintln!(
            "Python stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert!(output.status.success());
}

generate_cipher_suite_tests!(SUPPORTED_CIPHER_SUITES, 4);
