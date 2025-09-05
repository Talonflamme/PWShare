pub use record::readable_from_stream::ReadableFromStream;
pub use record::writable_to_sink::{WritableToSink, Sink};

pub mod tls_main;
mod record;
mod connection_state;