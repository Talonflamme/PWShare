use super::alert_description::AlertDescription;
use super::alert_level::AlertLevel;

pub struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}
