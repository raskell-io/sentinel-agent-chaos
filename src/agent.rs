//! Chaos Engineering agent implementation.

use crate::config::{Config, Experiment, Schedule};
use crate::faults::{apply_fault, FaultResult};
use crate::targeting::{is_excluded_path, CompiledTargeting};
use async_trait::async_trait;
use chrono::{Datelike, NaiveTime, Timelike, Utc};
use chrono_tz::Tz;
use sentinel_agent_sdk::prelude::*;
use sentinel_agent_sdk::v2::prelude::*;
use sentinel_agent_sdk::v2::{DrainReason, ShutdownReason, MetricsReport};
use sentinel_agent_protocol::v2::{CounterMetric, GaugeMetric};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Chaos Engineering agent.
pub struct ChaosAgent {
    config: Arc<Config>,
    compiled_experiments: Vec<CompiledExperiment>,
    /// Injection counts per experiment.
    injection_counts: Arc<HashMap<String, AtomicU64>>,
    /// Total requests processed.
    requests_total: AtomicU64,
    /// Total faults injected.
    faults_injected: AtomicU64,
    /// Whether the agent is draining (not accepting new fault injections).
    draining: AtomicBool,
}

/// Pre-compiled experiment for efficient matching.
struct CompiledExperiment {
    id: String,
    enabled: bool,
    targeting: CompiledTargeting,
    experiment: Experiment,
}

impl ChaosAgent {
    /// Create a new Chaos agent.
    pub fn new(config: Config) -> Self {
        let compiled_experiments: Vec<CompiledExperiment> = config
            .experiments
            .iter()
            .map(|exp| CompiledExperiment {
                id: exp.id.clone(),
                enabled: exp.enabled,
                targeting: CompiledTargeting::new(&exp.targeting),
                experiment: exp.clone(),
            })
            .collect();

        let injection_counts: HashMap<String, AtomicU64> = config
            .experiments
            .iter()
            .map(|exp| (exp.id.clone(), AtomicU64::new(0)))
            .collect();

        let enabled_count = compiled_experiments.iter().filter(|e| e.enabled).count();
        info!(
            experiments = compiled_experiments.len(),
            enabled = enabled_count,
            dry_run = config.settings.dry_run,
            "Chaos agent initialized"
        );

        Self {
            config: Arc::new(config),
            compiled_experiments,
            injection_counts: Arc::new(injection_counts),
            requests_total: AtomicU64::new(0),
            faults_injected: AtomicU64::new(0),
            draining: AtomicBool::new(false),
        }
    }

    /// Check if the agent is currently draining.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Get total requests processed.
    pub fn total_requests(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    /// Get total faults injected.
    pub fn total_faults_injected(&self) -> u64 {
        self.faults_injected.load(Ordering::Relaxed)
    }

    /// Flatten multi-value headers to single values.
    fn flatten_headers(headers: &HashMap<String, Vec<String>>) -> HashMap<String, String> {
        headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.first().cloned().unwrap_or_default()))
            .collect()
    }

    /// Check if chaos is currently active based on schedule.
    fn is_within_schedule(&self) -> bool {
        if self.config.safety.schedule.is_empty() {
            return true; // No schedule = always active
        }

        self.config.safety.schedule.iter().any(Self::check_schedule)
    }

    fn check_schedule(schedule: &Schedule) -> bool {
        // Parse timezone
        let tz: Tz = schedule
            .timezone
            .parse()
            .unwrap_or_else(|_| "UTC".parse().unwrap());

        let now = Utc::now().with_timezone(&tz);
        let day = now.weekday();
        let time = NaiveTime::from_hms_opt(
            now.hour(),
            now.minute(),
            now.second(),
        ).unwrap_or_default();

        // Check if current day is in the schedule
        if !schedule.days.contains(&day) {
            return false;
        }

        // Check if current time is within the window
        time >= schedule.start && time <= schedule.end
    }

    /// Find matching experiments for a request.
    fn find_matching_experiments(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> Vec<&CompiledExperiment> {
        self.compiled_experiments
            .iter()
            .filter(|exp| {
                exp.enabled && exp.targeting.matches(method, path, headers)
            })
            .collect()
    }

    /// Increment injection count for an experiment.
    fn increment_injection_count(&self, experiment_id: &str) {
        if let Some(counter) = self.injection_counts.get(experiment_id) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get injection count for an experiment.
    pub fn get_injection_count(&self, experiment_id: &str) -> u64 {
        self.injection_counts
            .get(experiment_id)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

#[async_trait]
impl Agent for ChaosAgent {
    fn name(&self) -> &str {
        "chaos"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Increment request counter
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Check global kill switch
        if !self.config.settings.enabled {
            debug!("Chaos agent disabled globally");
            return Decision::allow();
        }

        // Check if draining - don't inject new faults
        if self.is_draining() {
            debug!("Agent is draining, skipping fault injection");
            return Decision::allow();
        }

        // Check schedule
        if !self.is_within_schedule() {
            debug!("Outside scheduled chaos window");
            return Decision::allow();
        }

        let method = request.method();
        let path = request.path();
        let headers = Self::flatten_headers(request.headers());

        // Check excluded paths
        if is_excluded_path(path, &self.config.safety.excluded_paths) {
            debug!(path = path, "Path is excluded from chaos");
            return Decision::allow();
        }

        // Find matching experiments
        let matching = self.find_matching_experiments(method, path, &headers);
        if matching.is_empty() {
            debug!(path = path, method = method, "No matching experiments");
            return Decision::allow();
        }

        // Apply the first matching experiment that passes percentage check
        for exp in matching {
            if !exp.targeting.should_apply() {
                debug!(
                    experiment = %exp.id,
                    "Experiment matched but not selected by percentage"
                );
                continue;
            }

            // Apply the fault
            let result = apply_fault(
                &exp.experiment.fault,
                &exp.id,
                self.config.settings.dry_run,
                self.config.settings.log_injections,
            )
            .await;

            self.increment_injection_count(&exp.id);
            self.faults_injected.fetch_add(1, Ordering::Relaxed);

            match result {
                FaultResult::Allow { delay } => {
                    if let Some(d) = delay {
                        debug!(
                            experiment = %exp.id,
                            delay_ms = d.as_millis(),
                            "Fault applied with delay, allowing request"
                        );
                    }
                    // For latency faults, we've already applied the delay
                    // Allow the request to continue
                    return Decision::allow()
                        .with_tag(format!("chaos:{}", exp.id));
                }
                FaultResult::Block(decision) => {
                    return *decision;
                }
            }
        }

        // No experiment was applied
        Decision::allow()
    }

    async fn on_response(&self, _request: &Request, _response: &Response) -> Decision {
        // Chaos agent only operates on requests
        Decision::allow()
    }

    async fn on_configure(&self, config: serde_json::Value) -> Result<(), String> {
        // v2 configuration update support
        if config.is_null() {
            return Ok(());
        }

        // Log the configuration update
        info!(
            config = %config,
            "Received configuration update"
        );

        // For now, we just acknowledge the config - full hot-reload would require
        // more complex state management
        Ok(())
    }
}

/// v2 Protocol implementation for ChaosAgent.
impl AgentV2 for ChaosAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("chaos", "Chaos Engineering Agent", env!("CARGO_PKG_VERSION"))
            .with_config_push(true)
            .with_health_reporting(true)
            .with_metrics_export(true)
            .with_concurrent_requests(100)
            .with_cancellation(true)
            .with_max_processing_time_ms(5000)
    }

    fn health_status(&self) -> HealthStatus {
        // Report healthy unless we're draining
        if self.is_draining() {
            HealthStatus::degraded(
                "chaos",
                vec!["fault-injection".to_string()],
                1.0,
            )
        } else {
            HealthStatus::healthy("chaos")
        }
    }

    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("chaos", 10_000);

        // Add counter metrics
        report.counters.push(CounterMetric::new(
            "chaos_requests_total",
            self.total_requests(),
        ));

        report.counters.push(CounterMetric::new(
            "chaos_faults_injected_total",
            self.total_faults_injected(),
        ));

        // Add per-experiment injection counts
        for (experiment_id, counter) in self.injection_counts.iter() {
            let mut metric = CounterMetric::new(
                "chaos_experiment_injections_total",
                counter.load(Ordering::Relaxed),
            );
            metric.labels.insert("experiment".to_string(), experiment_id.clone());
            report.counters.push(metric);
        }

        // Add gauge metrics
        report.gauges.push(GaugeMetric::new(
            "chaos_experiments_enabled",
            self.compiled_experiments.iter().filter(|e| e.enabled).count() as f64,
        ));

        report.gauges.push(GaugeMetric::new(
            "chaos_agent_enabled",
            if self.config.settings.enabled { 1.0 } else { 0.0 },
        ));

        report.gauges.push(GaugeMetric::new(
            "chaos_agent_draining",
            if self.is_draining() { 1.0 } else { 0.0 },
        ));

        Some(report)
    }

    fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Chaos agent shutdown requested"
        );
        // Set draining flag to stop injecting new faults
        self.draining.store(true, Ordering::SeqCst);
    }

    fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        warn!(
            reason = ?reason,
            duration_ms = duration_ms,
            "Chaos agent drain requested - stopping fault injection"
        );
        self.draining.store(true, Ordering::SeqCst);
    }

    fn on_stream_closed(&self) {
        debug!("gRPC stream closed");
    }
}

// Safety: ChaosAgent is Send + Sync because all its fields are Send + Sync
unsafe impl Send for ChaosAgent {}
unsafe impl Sync for ChaosAgent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Fault, PathMatcher, SafetyConfig, Settings, Targeting};

    fn create_test_config(experiments: Vec<Experiment>) -> Config {
        Config {
            settings: Settings {
                enabled: true,
                dry_run: false,
                log_injections: false,
            },
            safety: SafetyConfig {
                max_affected_percent: 100,
                schedule: vec![],
                excluded_paths: vec!["/health".to_string()],
            },
            experiments,
        }
    }

    fn create_latency_experiment(id: &str, path_prefix: &str, delay_ms: u64) -> Experiment {
        Experiment {
            id: id.to_string(),
            enabled: true,
            description: "Test latency".to_string(),
            targeting: Targeting {
                paths: vec![PathMatcher::Prefix { prefix: path_prefix.to_string() }],
                methods: vec![],
                headers: HashMap::new(),
                percentage: 100,
            },
            fault: Fault::Latency {
                fixed_ms: delay_ms,
                min_ms: 0,
                max_ms: 0,
            },
        }
    }

    fn create_error_experiment(id: &str, path_prefix: &str, status: u16) -> Experiment {
        Experiment {
            id: id.to_string(),
            enabled: true,
            description: "Test error".to_string(),
            targeting: Targeting {
                paths: vec![PathMatcher::Prefix { prefix: path_prefix.to_string() }],
                methods: vec![],
                headers: HashMap::new(),
                percentage: 100,
            },
            fault: Fault::Error {
                status,
                message: Some("Test error".to_string()),
                headers: HashMap::new(),
            },
        }
    }

    #[test]
    fn test_agent_initialization() {
        let config = create_test_config(vec![
            create_latency_experiment("exp1", "/api/", 100),
            create_error_experiment("exp2", "/test/", 500),
        ]);

        let agent = ChaosAgent::new(config);
        assert_eq!(agent.compiled_experiments.len(), 2);
    }

    #[test]
    fn test_flatten_headers() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), vec!["application/json".to_string()]);
        headers.insert("X-Test".to_string(), vec!["value1".to_string(), "value2".to_string()]);

        let flat = ChaosAgent::flatten_headers(&headers);
        assert_eq!(flat.get("content-type"), Some(&"application/json".to_string()));
        assert_eq!(flat.get("x-test"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_find_matching_experiments() {
        let config = create_test_config(vec![
            create_latency_experiment("api-latency", "/api/", 100),
            create_error_experiment("test-error", "/test/", 500),
        ]);

        let agent = ChaosAgent::new(config);
        let headers = HashMap::new();

        // Should match api-latency
        let matches = agent.find_matching_experiments("GET", "/api/users", &headers);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "api-latency");

        // Should match test-error
        let matches = agent.find_matching_experiments("GET", "/test/something", &headers);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "test-error");

        // Should match nothing
        let matches = agent.find_matching_experiments("GET", "/other", &headers);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_injection_counts() {
        let config = create_test_config(vec![
            create_latency_experiment("exp1", "/api/", 100),
        ]);

        let agent = ChaosAgent::new(config);

        assert_eq!(agent.get_injection_count("exp1"), 0);

        agent.increment_injection_count("exp1");
        assert_eq!(agent.get_injection_count("exp1"), 1);

        agent.increment_injection_count("exp1");
        assert_eq!(agent.get_injection_count("exp1"), 2);
    }

    #[test]
    fn test_disabled_experiment() {
        let mut exp = create_latency_experiment("disabled", "/api/", 100);
        exp.enabled = false;

        let config = create_test_config(vec![exp]);
        let agent = ChaosAgent::new(config);

        let matches = agent.find_matching_experiments("GET", "/api/test", &HashMap::new());
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_schedule_check() {
        use chrono::Weekday;

        // Create a schedule that's always valid (all days, all hours)
        let schedule = Schedule {
            days: vec![
                Weekday::Mon, Weekday::Tue, Weekday::Wed,
                Weekday::Thu, Weekday::Fri, Weekday::Sat, Weekday::Sun,
            ],
            start: NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            end: NaiveTime::from_hms_opt(23, 59, 59).unwrap(),
            timezone: "UTC".to_string(),
        };

        assert!(ChaosAgent::check_schedule(&schedule));
    }

    #[test]
    fn test_v2_capabilities() {
        let config = create_test_config(vec![]);
        let agent = ChaosAgent::new(config);

        let caps = agent.capabilities();
        assert_eq!(caps.agent_id, "chaos");
        assert_eq!(caps.name, "Chaos Engineering Agent");
        assert!(caps.features.config_push);
        assert!(caps.features.health_reporting);
        assert!(caps.features.metrics_export);
        assert_eq!(caps.features.concurrent_requests, 100);
    }

    #[test]
    fn test_v2_health_status() {
        let config = create_test_config(vec![]);
        let agent = ChaosAgent::new(config);

        // Should be healthy initially
        let health = agent.health_status();
        assert!(health.is_healthy());
        assert_eq!(health.agent_id, "chaos");
    }

    #[test]
    fn test_v2_health_status_draining() {
        let config = create_test_config(vec![]);
        let agent = ChaosAgent::new(config);

        // Trigger drain
        agent.on_drain(5000, sentinel_agent_sdk::v2::DrainReason::Maintenance);

        // Should be degraded now
        let health = agent.health_status();
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_v2_metrics_report() {
        let config = create_test_config(vec![
            create_latency_experiment("exp1", "/api/", 100),
        ]);
        let agent = ChaosAgent::new(config);

        let report = agent.metrics_report();
        assert!(report.is_some());

        let report = report.unwrap();
        assert_eq!(report.agent_id, "chaos");
        assert!(!report.counters.is_empty());
        assert!(!report.gauges.is_empty());
    }

    #[test]
    fn test_draining_flag() {
        let config = create_test_config(vec![]);
        let agent = ChaosAgent::new(config);

        assert!(!agent.is_draining());

        agent.on_shutdown(sentinel_agent_sdk::v2::ShutdownReason::Graceful, 30000);

        assert!(agent.is_draining());
    }

    #[test]
    fn test_request_counters() {
        let config = create_test_config(vec![]);
        let agent = ChaosAgent::new(config);

        assert_eq!(agent.total_requests(), 0);
        assert_eq!(agent.total_faults_injected(), 0);

        // Simulate incrementing (in real usage this happens in on_request)
        agent.requests_total.fetch_add(1, Ordering::Relaxed);
        assert_eq!(agent.total_requests(), 1);
    }
}
