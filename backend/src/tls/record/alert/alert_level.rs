use pwshare_macros::{ReadableFromStream, WritableToSink};

#[repr(u8)]
#[derive(ReadableFromStream, WritableToSink, Debug, PartialEq, Eq)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}
