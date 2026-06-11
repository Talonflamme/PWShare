use crate::measure::{MeasurementMode, Measurer};
use rand::rngs::ChaCha8Rng;
use rand::{Rng, SeedableRng};
use std::hint::black_box;
use crate::result::BenchResult;

/// Tests with less than this value are not evaluated.
const T_TEST_MIN_SIZE: usize = 5000;

const NUMBER_PERCENTILES: usize = 100;

/// How many t-tests are performed on the same data. Each test has a different crop threshold.
const AMOUNT_T_TESTS: usize = 100; // TODO: +2?

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Left,
    Right,
}

pub(crate) struct Runtime {
    /// The runtimes of *all* runs, without cropping.
    pub(crate) all_runtimes: Vec<u64>,
    /// Index into `all_runtimes` at which cropping begins. Values at indices above `crop_end`
    /// are considered outliers and excluded from t-tests.
    crop_start: usize,
}

impl Runtime {
    fn new() -> Self {
        Self {
            all_runtimes: Vec::new(),
            crop_start: 0,
        }
    }

    fn push(&mut self, value: u64) {
        self.all_runtimes.push(value);
    }

    fn cropped(&self) -> &[u64] {
        &self.all_runtimes[..self.crop_start]
    }

    /// Execution time of programs are positively skewed, i.e. a few tests take significantly
    /// longer than usual. That can for example happen due to OS interrupts.
    /// We filter out some percentage of tests, depending on `p`.
    fn set_crop_percentile(&mut self, p: f64) {
        let index = (self.all_runtimes.len() as f64 * (1.0 - p)) as usize;
        self.crop_start = index;
    }

    fn len(&self) -> f64 {
        self.crop_start as f64
    }

    fn mean(&self) -> f64 {
        self.cropped().iter().sum::<u64>() as f64 / self.len()
    }

    fn variance(&self, mean: f64) -> f64 {
        // Bessel's correction, by using variance and mean on the same sample set we lose one degree of freedom and have to subtract 1
        let len_minus_1 = self.len() - 1.0;

        self.cropped()
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / len_minus_1
    }
}

pub struct Bencher {
    pub(crate) name: String,
    measurer: Measurer,

    pub(crate) runtime_left: Runtime,
    pub(crate) runtime_right: Runtime,
}

fn get_percentile(test_index: usize) -> f64 {
    1.0 - 0.5_f64.powf(10.0 * (test_index + 1) as f64 / NUMBER_PERCENTILES as f64)
}

impl Bencher {
    pub fn run_one<T, F: FnOnce() -> T>(&mut self, class: Class, f: F) {
        let start = self.measurer.now();
        black_box(f());
        let end = self.measurer.now();

        let runtime = end.difference(&start);

        match class {
            Class::Left => self.runtime_left.push(runtime),
            Class::Right => self.runtime_right.push(runtime),
        }
    }

    /// Benches by calling the `runner_func`. Runs `AMOUNT_T_TESTS` t-tests on the same
    /// data (tests differ by cropping-values) and returns the
    /// maximum t-statistic by any of those tests.
    ///
    /// A `max-t` > 5 suggests that the function tested is *not* constant time.
    ///
    /// A `max-t` < 5 does not mean the function is constant time, but also has
    /// no evidence of it being variable time.
    pub fn bench<F: Fn(&mut Self, &mut dyn Rng)>(mut self, runner_func: F) -> BenchResult {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // collect measurements
        runner_func(&mut self, &mut rng);

        // post-processing
        // sorting required for cropping to work
        self.runtime_left.all_runtimes.sort_unstable();
        self.runtime_right.all_runtimes.sort_unstable();

        // do t-tests
        let t_statistics = self.perform_t_tests();
        BenchResult::new(self, t_statistics)
    }

    fn perform_t_tests(&mut self) -> Vec<f64> {
        (0..AMOUNT_T_TESTS)
            .filter_map(|i| {
                let p = get_percentile(i);
                self.runtime_left.set_crop_percentile(p);
                self.runtime_right.set_crop_percentile(p);
                self.compute_t_statistic()
            })
            .collect()
    }

    /// Computes the `statistic t` of a
    /// [Welch's test](https://en.wikipedia.org/wiki/Welch%27s_t-test).
    ///
    /// Returns `Some(t)` if the test is significant, i.e. both classes have at least
    /// `T_TEST_MIN_SIZE` samples.
    ///
    /// Returns `None` if the test is insignificant.
    fn compute_t_statistic(&mut self) -> Option<f64> {
        let n1 = self.runtime_left.len();
        let n2 = self.runtime_right.len();

        if n1 < T_TEST_MIN_SIZE as f64 || n2 < T_TEST_MIN_SIZE as f64 {
            return None;
        }

        let m1 = self.runtime_left.mean();
        let v1 = self.runtime_left.variance(m1);

        let m2 = self.runtime_right.mean();
        let v2 = self.runtime_right.variance(m2);

        Some((m1 - m2).abs() / (v1 / n1 + v2 / n2).sqrt())
    }
}

#[derive(Default)]
pub struct BenchBuilder {
    name: Option<String>,
    mode: MeasurementMode,
}

impl BenchBuilder {
    pub fn builder() -> Self {
        Default::default()
    }

    pub fn name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn measure_mode(mut self, mode: MeasurementMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn build(self) -> Result<Bencher, String> {
        Ok(Bencher {
            name: self
                .name
                .ok_or("Name is required. Use `builder.name(...)`")?,
            measurer: Measurer::new(self.mode),
            runtime_left: Runtime::new(),
            runtime_right: Runtime::new(),
        })
    }
}
