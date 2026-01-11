//! Chaos Engineering Agent for Sentinel.
//!
//! Provides controlled fault injection for resilience testing including:
//! - Latency injection (fixed or random range)
//! - Error injection (HTTP status codes)
//! - Timeout simulation
//! - Response corruption
//! - Connection reset simulation
//!
//! # Safety Controls
//!
//! - Schedule windows (only active during specified times)
//! - Excluded paths (health checks always pass)
//! - Maximum affected percentage
//! - Global kill switch
//! - Dry run mode

pub mod agent;
pub mod config;
pub mod faults;
pub mod targeting;

pub use agent::ChaosAgent;
pub use config::Config;
