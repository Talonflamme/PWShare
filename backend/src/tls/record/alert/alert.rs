use super::alert_description::AlertDescription;
use super::alert_level::AlertLevel;
use pwshare_macros::{ReadableFromStream, WritableToSink};
use std::io::Error;

#[derive(ReadableFromStream, WritableToSink, Debug)]
pub struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}

impl From<Error> for Alert {
    fn from(value: Error) -> Self {
        Alert { level: AlertLevel::Fatal, description: AlertDescription::DevOnly }
    }
}
