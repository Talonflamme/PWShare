use pwshare_macros::ReadableFromStream;

#[repr(u8)]
#[derive(ReadableFromStream, Clone, Copy, Debug)]
pub enum HashAlgorithm {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6
}