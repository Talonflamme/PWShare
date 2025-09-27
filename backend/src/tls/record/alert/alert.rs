use pwshare_macros::{ReadableFromStream, WritableToSink};
use super::alert_description::AlertDescription;
use super::alert_level::AlertLevel;

#[derive(ReadableFromStream, WritableToSink, Debug)]
pub struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}
