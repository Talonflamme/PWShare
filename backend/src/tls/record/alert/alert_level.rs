use pwshare_macros::{ReadableFromStream, WritableToSink};

#[repr(u8)]
#[derive(ReadableFromStream, WritableToSink, Debug)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}
