//! TERAS configuration.

use serde::{Deserialize, Serialize};

/// TERAS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerasConfig {
    /// Component name for audit logs.
    pub component_name: String,

    /// Enable verbose logging.
    pub verbose: bool,

    /// Data directory for persistent storage.
    pub data_dir: Option<String>,

    /// Maximum indicators to keep in memory.
    pub max_indicators: usize,

    /// Feed fetch timeout in seconds.
    pub feed_timeout_secs: u64,
}

impl Default for TerasConfig {
    fn default() -> Self {
        Self {
            component_name: "teras".to_string(),
            verbose: false,
            data_dir: None,
            max_indicators: 100_000,
            feed_timeout_secs: 30,
        }
    }
}

impl TerasConfig {
    /// Create config for a specific component.
    #[must_use]
    pub fn for_component(name: impl Into<String>) -> Self {
        Self {
            component_name: name.into(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TerasConfig::default();
        assert_eq!(config.component_name, "teras");
        assert!(!config.verbose);
    }

    #[test]
    fn test_component_config() {
        let config = TerasConfig::for_component("gapura");
        assert_eq!(config.component_name, "gapura");
    }

    #[test]
    fn test_config_serialization() {
        let config = TerasConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"component_name\":\"teras\""));
    }
}
