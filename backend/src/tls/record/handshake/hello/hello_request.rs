use pwshare_macros::{ReadableFromStream, WritableToSink};

#[derive(Debug, ReadableFromStream, WritableToSink)]
/// The Hello Request message is empty.
pub struct HelloRequest;
