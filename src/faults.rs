//! Fault injection implementations.

use crate::config::Fault;
use rand::Rng;
use sentinel_agent_sdk::Decision;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info};

/// Result of applying a fault.
#[derive(Debug)]
pub enum FaultResult {
    /// Request should be allowed after optional delay.
    Allow { delay: Option<Duration> },
    /// Request should be blocked with a response.
    Block(Decision),
}

/// Apply a fault to a request.
pub async fn apply_fault(
    fault: &Fault,
    experiment_id: &str,
    dry_run: bool,
    log_injections: bool,
) -> FaultResult {
    match fault {
        Fault::Latency { fixed_ms, min_ms, max_ms } => {
            apply_latency(*fixed_ms, *min_ms, *max_ms, experiment_id, dry_run, log_injections).await
        }
        Fault::Error { status, message, headers } => {
            apply_error(*status, message.as_deref(), headers, experiment_id, dry_run, log_injections)
        }
        Fault::Timeout { duration_ms } => {
            apply_timeout(*duration_ms, experiment_id, dry_run, log_injections).await
        }
        Fault::Throttle { bytes_per_second } => {
            apply_throttle(*bytes_per_second, experiment_id, dry_run, log_injections)
        }
        Fault::Corrupt { probability } => {
            apply_corrupt(*probability, experiment_id, dry_run, log_injections)
        }
        Fault::Reset => {
            apply_reset(experiment_id, dry_run, log_injections)
        }
    }
}

/// Apply latency fault - add delay before proxying.
async fn apply_latency(
    fixed_ms: u64,
    min_ms: u64,
    max_ms: u64,
    experiment_id: &str,
    dry_run: bool,
    log_injections: bool,
) -> FaultResult {
    let delay_ms = if fixed_ms > 0 {
        fixed_ms
    } else if max_ms > min_ms {
        let mut rng = rand::thread_rng();
        rng.gen_range(min_ms..=max_ms)
    } else {
        min_ms
    };

    let duration = Duration::from_millis(delay_ms);

    if log_injections {
        info!(
            experiment = experiment_id,
            delay_ms = delay_ms,
            dry_run = dry_run,
            "Injecting latency fault"
        );
    }

    if !dry_run {
        tokio::time::sleep(duration).await;
    }

    FaultResult::Allow { delay: Some(duration) }
}

/// Apply error fault - return HTTP error immediately.
fn apply_error(
    status: u16,
    message: Option<&str>,
    headers: &HashMap<String, String>,
    experiment_id: &str,
    dry_run: bool,
    log_injections: bool,
) -> FaultResult {
    if log_injections {
        info!(
            experiment = experiment_id,
            status = status,
            dry_run = dry_run,
            "Injecting error fault"
        );
    }

    if dry_run {
        return FaultResult::Allow { delay: None };
    }

    let body = message.unwrap_or("Chaos fault injected");

    let mut decision = Decision::block(status)
        .with_block_header("content-type", "text/plain; charset=utf-8")
        .with_block_header("x-chaos-injected", "true")
        .with_block_header("x-chaos-experiment", experiment_id)
        .with_body(body.to_string())
        .with_tag(&format!("chaos:{}", experiment_id));

    for (name, value) in headers {
        decision = decision.with_block_header(name, value);
    }

    FaultResult::Block(decision)
}

/// Apply timeout fault - sleep then return 504 Gateway Timeout.
async fn apply_timeout(
    duration_ms: u64,
    experiment_id: &str,
    dry_run: bool,
    log_injections: bool,
) -> FaultResult {
    if log_injections {
        info!(
            experiment = experiment_id,
            duration_ms = duration_ms,
            dry_run = dry_run,
            "Injecting timeout fault"
        );
    }

    if dry_run {
        return FaultResult::Allow { delay: None };
    }

    // Sleep for the specified duration
    tokio::time::sleep(Duration::from_millis(duration_ms)).await;

    // Return 504 Gateway Timeout
    let decision = Decision::block(504)
        .with_block_header("content-type", "text/plain; charset=utf-8")
        .with_block_header("x-chaos-injected", "true")
        .with_block_header("x-chaos-experiment", experiment_id)
        .with_body("Gateway Timeout (chaos fault)".to_string())
        .with_tag(&format!("chaos:{}", experiment_id));

    FaultResult::Block(decision)
}

/// Apply throttle fault - return metadata for slow response delivery.
/// Note: Actual throttling would need to be implemented at the proxy level.
/// This fault adds headers to indicate throttling should be applied.
fn apply_throttle(
    bytes_per_second: u64,
    experiment_id: &str,
    dry_run: bool,
    log_injections: bool,
) -> FaultResult {
    if log_injections {
        info!(
            experiment = experiment_id,
            bytes_per_second = bytes_per_second,
            dry_run = dry_run,
            "Injecting throttle fault"
        );
    }

    if dry_run {
        return FaultResult::Allow { delay: None };
    }

    // For throttling, we allow the request but add metadata
    // The proxy would need to interpret this and throttle the response
    debug!(
        experiment = experiment_id,
        bytes_per_second = bytes_per_second,
        "Throttle fault - request allowed with throttle metadata"
    );

    // Since we can't actually throttle at the agent level,
    // we'll add a significant delay as a simple approximation
    // Assume average response of 10KB, calculate delay
    let estimated_bytes = 10_240u64;
    let delay_ms = (estimated_bytes * 1000) / bytes_per_second;

    FaultResult::Allow { delay: Some(Duration::from_millis(delay_ms)) }
}

/// Apply corrupt fault - inject garbage into response.
fn apply_corrupt(
    probability: f64,
    experiment_id: &str,
    dry_run: bool,
    log_injections: bool,
) -> FaultResult {
    let mut rng = rand::thread_rng();
    let should_corrupt = rng.gen::<f64>() < probability;

    if !should_corrupt {
        debug!(
            experiment = experiment_id,
            probability = probability,
            "Corrupt fault - not triggered this time"
        );
        return FaultResult::Allow { delay: None };
    }

    if log_injections {
        info!(
            experiment = experiment_id,
            probability = probability,
            dry_run = dry_run,
            "Injecting corrupt fault"
        );
    }

    if dry_run {
        return FaultResult::Allow { delay: None };
    }

    // Generate garbage response
    let garbage = generate_garbage();

    let decision = Decision::block(200)
        .with_block_header("content-type", "application/octet-stream")
        .with_block_header("x-chaos-injected", "true")
        .with_block_header("x-chaos-experiment", experiment_id)
        .with_body(garbage)
        .with_tag(&format!("chaos:{}", experiment_id));

    FaultResult::Block(decision)
}

/// Apply reset fault - simulate connection reset.
fn apply_reset(
    experiment_id: &str,
    dry_run: bool,
    log_injections: bool,
) -> FaultResult {
    if log_injections {
        info!(
            experiment = experiment_id,
            dry_run = dry_run,
            "Injecting connection reset fault"
        );
    }

    if dry_run {
        return FaultResult::Allow { delay: None };
    }

    // We can't actually reset the connection at the agent level,
    // so we return a 502 Bad Gateway to simulate upstream failure
    let decision = Decision::block(502)
        .with_block_header("content-type", "text/plain; charset=utf-8")
        .with_block_header("x-chaos-injected", "true")
        .with_block_header("x-chaos-experiment", experiment_id)
        .with_body("Connection reset (chaos fault)".to_string())
        .with_tag(&format!("chaos:{}", experiment_id));

    FaultResult::Block(decision)
}

/// Generate random garbage data.
fn generate_garbage() -> String {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(50..500);
    (0..len)
        .map(|_| rng.gen_range(0x20..0x7e) as u8 as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_latency_fault_fixed() {
        let fault = Fault::Latency {
            fixed_ms: 100,
            min_ms: 0,
            max_ms: 0,
        };

        let start = std::time::Instant::now();
        let result = apply_fault(&fault, "test", false, false).await;
        let elapsed = start.elapsed();

        assert!(matches!(result, FaultResult::Allow { delay: Some(_) }));
        assert!(elapsed >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_latency_fault_dry_run() {
        let fault = Fault::Latency {
            fixed_ms: 1000,
            min_ms: 0,
            max_ms: 0,
        };

        let start = std::time::Instant::now();
        let result = apply_fault(&fault, "test", true, false).await;
        let elapsed = start.elapsed();

        assert!(matches!(result, FaultResult::Allow { delay: Some(_) }));
        // Should be much faster in dry run mode
        assert!(elapsed < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_error_fault() {
        let fault = Fault::Error {
            status: 503,
            message: Some("Service Unavailable".to_string()),
            headers: HashMap::new(),
        };

        let result = apply_fault(&fault, "test", false, false).await;
        assert!(matches!(result, FaultResult::Block(_)));
    }

    #[tokio::test]
    async fn test_error_fault_dry_run() {
        let fault = Fault::Error {
            status: 503,
            message: None,
            headers: HashMap::new(),
        };

        let result = apply_fault(&fault, "test", true, false).await;
        // Dry run should allow the request
        assert!(matches!(result, FaultResult::Allow { delay: None }));
    }

    #[tokio::test]
    async fn test_timeout_fault() {
        let fault = Fault::Timeout { duration_ms: 50 };

        let start = std::time::Instant::now();
        let result = apply_fault(&fault, "test", false, false).await;
        let elapsed = start.elapsed();

        assert!(matches!(result, FaultResult::Block(_)));
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_corrupt_fault_zero_probability() {
        let fault = Fault::Corrupt { probability: 0.0 };

        // Should never corrupt with 0 probability
        for _ in 0..10 {
            let result = apply_fault(&fault, "test", false, false).await;
            assert!(matches!(result, FaultResult::Allow { delay: None }));
        }
    }

    #[tokio::test]
    async fn test_corrupt_fault_full_probability() {
        let fault = Fault::Corrupt { probability: 1.0 };

        // Should always corrupt with 1.0 probability
        let result = apply_fault(&fault, "test", false, false).await;
        assert!(matches!(result, FaultResult::Block(_)));
    }

    #[tokio::test]
    async fn test_reset_fault() {
        let fault = Fault::Reset;

        let result = apply_fault(&fault, "test", false, false).await;
        assert!(matches!(result, FaultResult::Block(_)));
    }

    #[test]
    fn test_generate_garbage() {
        let garbage = generate_garbage();
        assert!(!garbage.is_empty());
        assert!(garbage.len() >= 50);
        assert!(garbage.len() < 500);
    }
}
