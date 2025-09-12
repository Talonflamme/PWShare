use pwshare_macros::{ReadableFromStream, WritableToSink};
use rand::rngs::OsRng;
use rand_chacha::rand_core::RngCore;

#[derive(Debug, PartialEq, Eq, ReadableFromStream, WritableToSink)]
pub struct Random {
    gmt_unix_time: u32,
    random_bytes: [u8; 28],
}

impl Random {
    /// Generates a random `Random` struct. Each byte (including the gmt_unix_time) is
    /// generated randomly.
    pub fn generate() -> Random {
        let rng = &mut OsRng;
        let gmt_unix_time = rng.next_u32();
        
        let mut random_bytes = [0; 28];
        rng.fill_bytes(&mut random_bytes);
        
        Random {
            gmt_unix_time,
            random_bytes
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut res = [0; 32];

        res[..4].copy_from_slice(&self.gmt_unix_time.to_be_bytes());
        res[4..].copy_from_slice(&self.random_bytes);

        res
    }
}
