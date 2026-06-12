mod cctf_bencher;
mod measure;
mod result;

use crate::cctf_bencher::{BenchBuilder, Bencher, Class};
use crate::measure::MeasurementMode;
use rand::{Rng, RngExt};

fn rand_vec(len: usize, rng: &mut dyn Rng) -> Vec<u8> {
    let mut rand = vec![0; len];
    rng.fill_bytes(&mut rand);
    rand
}

fn is_all_zero(vec: Vec<u8>) -> bool {
    // vartime
    vec.iter().copied().all(|b| b == 0)

    // ct
    // vec.iter().copied().reduce(|a, b| a | b).unwrap() == 0
}

fn main() {
    let bencher = BenchBuilder::builder()
        .name("All-Zero")
        .measure_mode(MeasurementMode::Time) // TODO: CpuCycles returns inf
        .build()
        .unwrap();

    let vlen: usize = 100;
    let runner = Bencher::generator(
        is_all_zero,
        |rng| rand_vec(vlen, rng),
        vec![0; vlen],
        1_000_000,
    );

    let result = bencher.bench(runner);

    println!("{}", result);
}
