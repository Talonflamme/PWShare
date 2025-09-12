use once_cell::sync::Lazy;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::sync::Mutex;

pub static RNG: Lazy<Mutex<ChaCha8Rng>> = Lazy::new(|| {
    let seed = 42;
    Mutex::new(ChaCha8Rng::seed_from_u64(seed))
});

macro_rules! rng {
    () => {
        *crate::cryptography::rng::RNG.lock().unwrap()
    };
}

pub(crate) use rng;
