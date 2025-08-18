use pwshare_macros::ReadableFromStream;

#[derive(Debug, PartialEq, Eq, ReadableFromStream)]
pub struct Random {
    gmt_unix_time: u32,
    random_bytes: [u8; 28],
}
