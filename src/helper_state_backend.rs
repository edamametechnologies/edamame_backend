use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, PartialOrd)]
pub enum HelperStateBackend {
    Disabled,
    Enabled,
    EnabledFullDisk,
    Outdated,
    Fatal,
    Unsupported,
}
