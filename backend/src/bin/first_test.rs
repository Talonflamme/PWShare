use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::{Rng, RngExt};

fn rand_vec(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut rand = vec![0; len];
    rng.fill_bytes(&mut rand);
    rand
}

fn is_all_zero(vec: &Vec<u8>) -> bool {
    // vartime
    // vec.iter().copied().all(|b| b == 0)

    // ct
    vec.iter().copied().reduce(|a, b| a | b).unwrap() == 0
}

fn all_zero(runner: &mut CtRunner, rng: &mut BenchRng) {
    let vlen = 100;
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    let fixed = vec![0; vlen]; // all zeros

    for _ in 0..100_000 {
        if rng.random::<bool>() {
            // test with random array of bytes
            let vec = rand_vec(vlen, rng);
            classes.push(Class::Right);
            inputs.push(vec);
        } else {
            let vec = fixed.clone();
            classes.push(Class::Left);
            inputs.push(vec);
        }
    }

    for (class, vec) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || is_all_zero(&vec));
    }
}

ctbench_main!(all_zero);
