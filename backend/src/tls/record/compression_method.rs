use pwshare_macros::{ReadableFromStream, WritableToSink};

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, ReadableFromStream, WritableToSink)]
pub enum CompressionMethod {
    Null = 0
}
