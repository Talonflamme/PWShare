use pwshare_macros::ReadableFromStream;

#[derive(Debug, ReadableFromStream)]
/// The Hello Request message is empty.
pub struct HelloRequest;
