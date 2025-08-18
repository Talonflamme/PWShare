#[derive(Debug, PartialEq, Eq)]
pub struct Random {
    pub gmt_unix_time: u32,
    pub random_bytes: [u8; 28],
}
