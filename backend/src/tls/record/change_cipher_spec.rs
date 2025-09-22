use pwshare_macros::{ReadableFromStream, WritableToSink};

#[repr(u8)]
#[derive(ReadableFromStream, WritableToSink)]
pub enum ChangeCipherSpec {
    ChangeCipherSpec = 1,
}
