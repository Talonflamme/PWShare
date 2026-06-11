use crate::cctf_bencher::Bencher;
use colored::{ColoredString, Colorize};
use std::fmt::{Display, Formatter};

const T_THRESHOLD_MODERATE: f64 = 10.0;
const T_THRESHOLD_DEFINITELY: f64 = 300.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Conclusion {
    DefinitelyVariableTime,
    ProbablyVariableTime,
    ProbablyConstantTime,
}

impl Display for Conclusion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Conclusion::DefinitelyVariableTime => "Definitely Variable Time",
            Conclusion::ProbablyVariableTime => "Probably Variable Time",
            Conclusion::ProbablyConstantTime => "Probably Constant Time",
        };
        write!(f, "{}", str)
    }
}

impl Conclusion {
    fn colorize<C: Colorize>(&self, string: C) -> ColoredString {
        match self {
            Conclusion::DefinitelyVariableTime => string.on_bright_red().bold(),
            Conclusion::ProbablyVariableTime => string.on_bright_red(),
            Conclusion::ProbablyConstantTime => string.on_green(),
        }
    }

    fn colorized(&self) -> ColoredString {
        let s = self.to_string();
        self.colorize(s.as_str())
    }
    
    pub fn is_probably_ct(&self) -> bool {
        match self {
            Conclusion::DefinitelyVariableTime => false,
            Conclusion::ProbablyVariableTime => false,
            Conclusion::ProbablyConstantTime => true,
        }
    }
}

#[derive(Debug)]
pub struct BenchResult {
    name: String,
    /// The maximum t-statistic of any executed t-test. A value > 5 means the function is likely
    /// not constant time.
    max_t: f64,
    /// How many `Class::Left` entries were used.
    sample_count_left: u64,
    /// How many `Class::Right` entries were used.
    sample_count_right: u64,
}

impl BenchResult {
    pub(crate) fn new(bench: Bencher, t_statistics: Vec<f64>) -> Self {
        let max_t = t_statistics.into_iter().fold(0.0, f64::max);

        Self {
            name: bench.name,
            max_t,
            sample_count_left: bench.runtime_left.all_runtimes.len() as u64,
            sample_count_right: bench.runtime_right.all_runtimes.len() as u64,
        }
    }

    pub fn conclusion(&self) -> Conclusion {
        if self.max_t >= T_THRESHOLD_DEFINITELY {
            Conclusion::DefinitelyVariableTime
        } else if self.max_t >= T_THRESHOLD_MODERATE {
            Conclusion::ProbablyVariableTime
        } else {
            Conclusion::ProbablyConstantTime
        }
    }
}

fn fmt_big_number(n: u64) -> String {
    match n {
        n if n >= 1_000_000_000 => format!("{:.1}B", n as f64 / 1_000_000_000.0),
        n if n >= 1_000_000 => format!("{:.1}M", n as f64 / 1_000_000.0),
        n if n >= 1_000 => format!("{:.1}K", n as f64 / 1_000.0),
        n => format!("{}", n),
    }
}

impl Display for BenchResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // name
        write!(f, "{}:\t", self.name.bold())?;
        // measurements
        write!(
            f,
            "[{}+{}] {}",
            fmt_big_number(self.sample_count_left).blue(),
            fmt_big_number(self.sample_count_right).red(),
            fmt_big_number(self.sample_count_left + self.sample_count_right)
        )?;
        // max t
        write!(f, ", max_t = {:+.2}", self.max_t)?;
        write!(f, ": {}", self.conclusion().colorized())?;
        write!(f, "{}", "".normal())?;
        Ok(())
    }
}
