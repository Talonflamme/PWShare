use pwshare_macros::ReadableFromStream;

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, ReadableFromStream)]
pub enum CompressionMethod {
    Null = 0
}
