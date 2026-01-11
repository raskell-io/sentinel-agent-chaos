//! Configuration types for the Chaos Engineering agent.

use anyhow::{anyhow, Result};
use chrono::{NaiveTime, Weekday};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Main configuration for the Chaos agent.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    /// Global settings.
    pub settings: Settings,
    /// Safety limits.
    pub safety: SafetyConfig,
    /// Fault experiments.
    #[serde(default)]
    pub experiments: Vec<Experiment>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            safety: SafetyConfig::default(),
            experiments: Vec::new(),
        }
    }
}

impl Config {
    /// Load configuration from a YAML file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate safety config
        if self.safety.max_affected_percent > 100 {
            return Err(anyhow!(
                "max_affected_percent must be between 0 and 100, got {}",
                self.safety.max_affected_percent
            ));
        }

        // Validate schedules
        for schedule in &self.safety.schedule {
            if schedule.start >= schedule.end {
                return Err(anyhow!(
                    "Schedule start time ({}) must be before end time ({})",
                    schedule.start,
                    schedule.end
                ));
            }
        }

        // Validate experiments
        let mut ids = std::collections::HashSet::new();
        for exp in &self.experiments {
            if !ids.insert(&exp.id) {
                return Err(anyhow!("Duplicate experiment id: {}", exp.id));
            }
            exp.validate()?;
        }

        Ok(())
    }
}

/// Global settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Settings {
    /// Global kill switch.
    pub enabled: bool,
    /// Log faults without applying them.
    pub dry_run: bool,
    /// Log when faults are injected.
    pub log_injections: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            dry_run: false,
            log_injections: true,
        }
    }
}

/// Safety configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SafetyConfig {
    /// Maximum percentage of traffic that can be affected.
    pub max_affected_percent: u8,
    /// Schedule windows when chaos is active.
    #[serde(default)]
    pub schedule: Vec<Schedule>,
    /// Paths that are never affected by chaos.
    #[serde(default)]
    pub excluded_paths: Vec<String>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            max_affected_percent: 50,
            schedule: Vec::new(),
            excluded_paths: vec![
                "/health".to_string(),
                "/ready".to_string(),
                "/metrics".to_string(),
            ],
        }
    }
}

/// Schedule window when chaos is active.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Schedule {
    /// Days of the week.
    #[serde(deserialize_with = "deserialize_weekdays")]
    pub days: Vec<Weekday>,
    /// Start time (HH:MM format).
    #[serde(deserialize_with = "deserialize_time")]
    pub start: NaiveTime,
    /// End time (HH:MM format).
    #[serde(deserialize_with = "deserialize_time")]
    pub end: NaiveTime,
    /// Timezone (e.g., "UTC", "America/New_York").
    #[serde(default = "default_timezone")]
    pub timezone: String,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

fn deserialize_time<'de, D>(deserializer: D) -> Result<NaiveTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    NaiveTime::parse_from_str(&s, "%H:%M").map_err(serde::de::Error::custom)
}

fn deserialize_weekdays<'de, D>(deserializer: D) -> Result<Vec<Weekday>, D::Error>
where
    D: Deserializer<'de>,
{
    let days: Vec<String> = Deserialize::deserialize(deserializer)?;
    days.into_iter()
        .map(|s| parse_weekday(&s).ok_or_else(|| serde::de::Error::custom(format!("Invalid weekday: {}", s))))
        .collect()
}

fn parse_weekday(s: &str) -> Option<Weekday> {
    match s.to_lowercase().as_str() {
        "mon" | "monday" => Some(Weekday::Mon),
        "tue" | "tuesday" => Some(Weekday::Tue),
        "wed" | "wednesday" => Some(Weekday::Wed),
        "thu" | "thursday" => Some(Weekday::Thu),
        "fri" | "friday" => Some(Weekday::Fri),
        "sat" | "saturday" => Some(Weekday::Sat),
        "sun" | "sunday" => Some(Weekday::Sun),
        _ => None,
    }
}

/// A fault experiment.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Experiment {
    /// Unique identifier for the experiment.
    pub id: String,
    /// Whether the experiment is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Targeting rules.
    pub targeting: Targeting,
    /// Fault to inject.
    pub fault: Fault,
}

fn default_true() -> bool {
    true
}

impl Experiment {
    /// Validate the experiment configuration.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(anyhow!("Experiment id cannot be empty"));
        }

        self.targeting.validate()?;
        self.fault.validate()?;

        Ok(())
    }
}

/// Targeting rules for an experiment.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct Targeting {
    /// Path matchers.
    #[serde(default)]
    pub paths: Vec<PathMatcher>,
    /// HTTP methods to match.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Headers that must be present with specific values.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Percentage of matching requests to affect (0-100).
    #[serde(default = "default_percentage")]
    pub percentage: u8,
}

fn default_percentage() -> u8 {
    100
}

impl Targeting {
    /// Validate the targeting configuration.
    pub fn validate(&self) -> Result<()> {
        if self.percentage > 100 {
            return Err(anyhow!(
                "Targeting percentage must be between 0 and 100, got {}",
                self.percentage
            ));
        }

        for path in &self.paths {
            path.validate()?;
        }

        Ok(())
    }
}

/// Path matching rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PathMatcher {
    /// Exact path match.
    Exact {
        exact: String,
    },
    /// Path prefix match.
    Prefix {
        prefix: String,
    },
    /// Regex pattern match.
    Regex {
        regex: String,
    },
}

impl PathMatcher {
    /// Validate the path matcher.
    pub fn validate(&self) -> Result<()> {
        if let PathMatcher::Regex { regex: pattern } = self {
            regex::Regex::new(pattern)
                .map_err(|e| anyhow!("Invalid regex pattern '{}': {}", pattern, e))?;
        }
        Ok(())
    }

    /// Get the path value for matching.
    pub fn value(&self) -> &str {
        match self {
            PathMatcher::Exact { exact } => exact,
            PathMatcher::Prefix { prefix } => prefix,
            PathMatcher::Regex { regex } => regex,
        }
    }
}

/// Fault types that can be injected.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Fault {
    /// Add latency before proxying.
    Latency {
        /// Fixed delay in milliseconds.
        #[serde(default)]
        fixed_ms: u64,
        /// Minimum delay for random range.
        #[serde(default)]
        min_ms: u64,
        /// Maximum delay for random range.
        #[serde(default)]
        max_ms: u64,
    },
    /// Return an HTTP error immediately.
    Error {
        /// HTTP status code.
        status: u16,
        /// Error message body.
        #[serde(default)]
        message: Option<String>,
        /// Additional headers.
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    /// Simulate an upstream timeout.
    Timeout {
        /// Duration to wait before returning 504.
        duration_ms: u64,
    },
    /// Throttle response bandwidth.
    Throttle {
        /// Bytes per second.
        bytes_per_second: u64,
    },
    /// Inject garbage into response.
    Corrupt {
        /// Probability of corruption (0.0-1.0).
        probability: f64,
    },
    /// Simulate connection reset.
    Reset,
}

impl Fault {
    /// Validate the fault configuration.
    pub fn validate(&self) -> Result<()> {
        match self {
            Fault::Latency { fixed_ms, min_ms, max_ms } => {
                if *fixed_ms == 0 && *min_ms == 0 && *max_ms == 0 {
                    return Err(anyhow!(
                        "Latency fault must specify either fixed_ms or min_ms/max_ms"
                    ));
                }
                if *fixed_ms == 0 && *max_ms < *min_ms {
                    return Err(anyhow!(
                        "Latency max_ms ({}) must be >= min_ms ({})",
                        max_ms,
                        min_ms
                    ));
                }
            }
            Fault::Error { status, .. } => {
                if *status < 100 || *status > 599 {
                    return Err(anyhow!("Invalid HTTP status code: {}", status));
                }
            }
            Fault::Timeout { duration_ms } => {
                if *duration_ms == 0 {
                    return Err(anyhow!("Timeout duration_ms must be > 0"));
                }
            }
            Fault::Throttle { bytes_per_second } => {
                if *bytes_per_second == 0 {
                    return Err(anyhow!("Throttle bytes_per_second must be > 0"));
                }
            }
            Fault::Corrupt { probability } => {
                if *probability < 0.0 || *probability > 1.0 {
                    return Err(anyhow!(
                        "Corrupt probability must be between 0.0 and 1.0, got {}",
                        probability
                    ));
                }
            }
            Fault::Reset => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.settings.enabled);
        assert!(!config.settings.dry_run);
        assert!(config.experiments.is_empty());
    }

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
settings:
  enabled: true
experiments: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.settings.enabled);
    }

    #[test]
    fn test_parse_latency_experiment() {
        let yaml = r#"
experiments:
  - id: "test-latency"
    targeting:
      paths:
        - prefix: "/api/"
      percentage: 10
    fault:
      type: latency
      fixed_ms: 500
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.experiments.len(), 1);
        assert_eq!(config.experiments[0].id, "test-latency");
        assert!(matches!(config.experiments[0].fault, Fault::Latency { fixed_ms: 500, .. }));
    }

    #[test]
    fn test_parse_error_experiment() {
        let yaml = r#"
experiments:
  - id: "test-error"
    targeting:
      percentage: 5
    fault:
      type: error
      status: 503
      message: "Service Unavailable"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(
            config.experiments[0].fault,
            Fault::Error { status: 503, .. }
        ));
    }

    #[test]
    fn test_parse_schedule() {
        let yaml = r#"
safety:
  schedule:
    - days: [mon, tue, wed]
      start: "09:00"
      end: "17:00"
      timezone: "UTC"
experiments: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.safety.schedule.len(), 1);
        assert_eq!(config.safety.schedule[0].days.len(), 3);
    }

    #[test]
    fn test_validation_fails_for_duplicate_ids() {
        let yaml = r#"
experiments:
  - id: "test"
    targeting:
      percentage: 10
    fault:
      type: latency
      fixed_ms: 100
  - id: "test"
    targeting:
      percentage: 10
    fault:
      type: latency
      fixed_ms: 200
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_for_invalid_percentage() {
        let yaml = r#"
experiments:
  - id: "test"
    targeting:
      percentage: 150
    fault:
      type: latency
      fixed_ms: 100
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_for_invalid_regex() {
        let yaml = r#"
experiments:
  - id: "test"
    targeting:
      paths:
        - regex: "[invalid"
    fault:
      type: latency
      fixed_ms: 100
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }
}
