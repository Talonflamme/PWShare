pub mod alert_level;
pub mod alert_description;
mod alert;

pub type Result<T> = core::result::Result<T, Alert>;
pub use alert::Alert;
