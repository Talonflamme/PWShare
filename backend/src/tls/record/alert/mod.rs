pub mod alert_level;
pub mod alert_description;
mod alert;

pub type AlertResult<T> = Result<T, Alert>;
pub use alert::Alert;
