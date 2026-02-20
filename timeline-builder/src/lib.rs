// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// timeline-builder/src/lib.rs
// NSM-20260218-002
#![forbid(unsafe_code)]

pub mod markers;
pub mod model;
pub mod time;
pub mod correlate;
pub mod render;
pub mod scenarios;

use telemetry_core::config::TelemetryConfig;
use telemetry_core::validation::validate as validate_cfg;

use crate::model::{Timeline, TimelineBuildError};
use crate::scenarios::{ScenarioId, ScenarioParams};

/// Build a deterministic, correlated, monotonically-timestamped timeline.
///
/// Determinism: same `TelemetryConfig.seed` + same `scenario_id` + same `params` => identical output.
pub fn kristoffersen_feb18_build_timeline(
    cfg: &TelemetryConfig,
    scenario_id: ScenarioId,
    params: ScenarioParams,
) -> Result<Timeline, TimelineBuildError> {
    validate_cfg(cfg).map_err(|e| TimelineBuildError::InvalidConfig(e.to_string()))?;

    let mut builder = scenarios::kristoffersen_feb18_scenario_builder(cfg, scenario_id, params)?;
    let timeline = builder.kristoffersen_feb18_build()?;
    timeline.kristoffersen_feb18_validate_invariants()?;
    Ok(timeline)
}

