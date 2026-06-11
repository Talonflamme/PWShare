use std::time::Instant;

#[derive(Debug)]
pub enum Timestamp {
    Time(Instant),
    CpuCycles(u64),
}

impl Timestamp {
    pub fn difference(&self, earlier: &Timestamp) -> u64 {
        match (self, earlier) {
            (Timestamp::Time(end), Timestamp::Time(start)) => {
                end.duration_since(*start).as_nanos() as u64
            }
            (Timestamp::CpuCycles(end), Timestamp::CpuCycles(start)) => end.wrapping_sub(*start),
            _ => panic!("mismatched timestamp modes"),
        }
    }
}

#[derive(Debug, Default)]
pub enum MeasurementMode {
    #[default]
    Time,
    CpuCycles,
}

#[derive(Debug)]
pub struct Measurer {
    mode: MeasurementMode,
}

impl Measurer {
    pub fn new(mode: MeasurementMode) -> Self {
        Self { mode }
    }

    pub fn now(&self) -> Timestamp {
        match self.mode {
            MeasurementMode::Time => Timestamp::Time(Instant::now()),
            MeasurementMode::CpuCycles => {
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    let mut aux = 0u32;
                    Timestamp::CpuCycles(std::arch::x86_64::__rdtscp(&mut aux))
                }
                #[cfg(not(target_arch = "x86_64"))]
                todo!()
            }
        }
    }
}
