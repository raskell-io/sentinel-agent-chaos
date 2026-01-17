//! Chaos Engineering Agent CLI.

use anyhow::Result;
use clap::Parser;
use sentinel_agent_chaos::{ChaosAgent, Config};
use sentinel_agent_sdk::v2::{AgentRunnerV2, TransportConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "sentinel-agent-chaos")]
#[command(about = "Chaos Engineering agent for Sentinel - controlled fault injection for resilience testing")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "chaos.yaml")]
    config: PathBuf,

    /// Unix socket path
    #[arg(short, long, default_value = "/tmp/sentinel-chaos.sock")]
    socket: PathBuf,

    /// gRPC server address (e.g., "0.0.0.0:50051")
    #[arg(long, value_name = "ADDR")]
    grpc_address: Option<SocketAddr>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'L', long, default_value = "info")]
    log_level: String,

    /// Print example configuration and exit
    #[arg(long)]
    print_config: bool,

    /// Validate configuration and exit
    #[arg(long)]
    validate: bool,

    /// Run in dry-run mode (log faults without applying)
    #[arg(long)]
    dry_run: bool,
}

fn print_example_config() {
    let example = r#"# Chaos Engineering Agent Configuration
# See https://sentinel.raskell.io/agents/chaos/ for full documentation

settings:
  enabled: true                    # Global kill switch
  dry_run: false                   # Log faults without applying
  log_injections: true             # Log when faults are injected

# Safety limits
safety:
  max_affected_percent: 50         # Never affect more than 50% of traffic
  schedule:                        # Only active during these windows
    - days: [mon, tue, wed, thu, fri]
      start: "09:00"
      end: "17:00"
      timezone: "UTC"
  excluded_paths:                  # Never inject faults here
    - "/health"
    - "/ready"
    - "/metrics"

# Fault experiments
experiments:
  # Example: Add latency to API calls
  - id: "api-latency"
    enabled: true
    description: "Add latency to API calls"
    targeting:
      paths:
        - prefix: "/api/"
      methods: ["GET", "POST"]
      percentage: 10               # Affect 10% of matching requests
    fault:
      type: latency
      fixed_ms: 500                # Fixed 500ms delay
      # OR random range:
      # min_ms: 100
      # max_ms: 1000

  # Example: Inject 500 errors
  - id: "payment-errors"
    enabled: true
    description: "Inject 500 errors into payment service"
    targeting:
      paths:
        - exact: "/api/payments"
      percentage: 5
    fault:
      type: error
      status: 500
      message: "Chaos: Internal Server Error"
      headers:
        x-chaos-injected: "true"

  # Example: Simulate upstream timeout
  - id: "upstream-timeout"
    enabled: false
    description: "Simulate upstream timeouts"
    targeting:
      paths:
        - regex: "^/api/external/.*"
      percentage: 2
    fault:
      type: timeout
      duration_ms: 30000           # 30 second timeout

  # Example: Header-triggered latency (for testing)
  - id: "header-triggered-latency"
    enabled: true
    description: "Add latency when X-Chaos-Latency header is present"
    targeting:
      headers:
        x-chaos-latency: "true"
      percentage: 100
    fault:
      type: latency
      min_ms: 1000
      max_ms: 3000
"#;
    println!("{}", example);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle --print-config
    if args.print_config {
        print_example_config();
        return Ok(());
    }

    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Load configuration
    info!(config = %args.config.display(), "Loading configuration");
    let mut config = Config::from_file(&args.config)?;

    // Override dry_run if specified on command line
    if args.dry_run {
        config.settings.dry_run = true;
        info!("Dry-run mode enabled via command line");
    }

    // Handle --validate
    if args.validate {
        info!("Configuration is valid");
        return Ok(());
    }

    // Create agent
    let agent = ChaosAgent::new(config);

    // Configure transport based on CLI options
    let transport = match args.grpc_address {
        Some(grpc_addr) => {
            info!(
                grpc_address = %grpc_addr,
                socket = %args.socket.display(),
                "Starting Chaos Engineering agent with gRPC and UDS (v2 protocol)"
            );
            TransportConfig::Both {
                grpc_address: grpc_addr,
                uds_path: args.socket,
            }
        }
        None => {
            info!(socket = %args.socket.display(), "Starting Chaos Engineering agent with UDS (v2 protocol)");
            TransportConfig::Uds { path: args.socket }
        }
    };

    // Run agent with v2 runner
    let mut runner = AgentRunnerV2::new(agent).with_name("chaos");

    runner = match transport {
        TransportConfig::Grpc { address } => runner.with_grpc(address),
        TransportConfig::Uds { path } => runner.with_uds(path),
        TransportConfig::Both { grpc_address, uds_path } => runner.with_both(grpc_address, uds_path),
    };

    runner.run().await?;

    Ok(())
}
