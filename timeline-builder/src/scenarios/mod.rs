// timeline-builder/src/scenarios/mod.rs
// NSM-20260218-002

use telemetry_core::config::TelemetryConfig;

use crate::correlate::kristoffersen_feb18_derive_scenario_seed;
use crate::model::TimelineBuildError;

pub mod t1059_001_encoded;
pub mod t1003_001_lsass;
pub mod t1040_network_discovery;

#[derive(Debug, Clone)]
pub struct ScenarioParams {
    /// If true, include encoded PowerShell indicator fields (telemetry narrative only).
    pub encoded_powershell: bool,
    /// Label only; does not affect capabilities.
    pub target_label: Option<String>,
}

impl Default for ScenarioParams {
    fn default() -> Self {
        Self { encoded_powershell: true, target_label: None }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ScenarioId {
    T1059_001_Encoded,
    T1003_001_LsassNarrative,
    T1040_NetworkDiscovery,
}

impl ScenarioId {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScenarioId::T1059_001_Encoded => "T1059.001_Encoded_20260218",
            ScenarioId::T1003_001_LsassNarrative => "T1003.001_LSASS_TelemetryNarrative_20260218",
            ScenarioId::T1040_NetworkDiscovery => "T1040_NetworkDiscovery_20260218",
        }
    }
}

pub struct ScenarioBuilder {
    cfg: TelemetryConfig,
    scenario_id: ScenarioId,
    params: ScenarioParams,
    scenario_seed: u64,
}

impl ScenarioBuilder {
    pub fn new(cfg: &TelemetryConfig, scenario_id: ScenarioId, params: ScenarioParams) -> Self {
        let params_norm = format!(
            "encoded_powershell={};target_label={}",
            params.encoded_powershell,
            params.target_label.clone().unwrap_or_else(|| "-".to_string())
        );
        let scenario_seed = kristoffersen_feb18_derive_scenario_seed(cfg.seed, scenario_id.as_str(), &params_norm);

        Self {
            cfg: cfg.clone(),
            scenario_id,
            params,
            scenario_seed,
        }
    }

    pub fn kristoffersen_feb18_build(&mut self) -> Result<crate::model::Timeline, TimelineBuildError> {
        match self.scenario_id {
            ScenarioId::T1059_001_Encoded => {
                t1059_001_encoded::kristoffersen_feb18_build(&self.cfg, self.scenario_seed, &self.params)
            }
            ScenarioId::T1003_001_LsassNarrative => {
                t1003_001_lsass::kristoffersen_feb18_build(&self.cfg, self.scenario_seed, &self.params)
            }
            ScenarioId::T1040_NetworkDiscovery => {
                t1040_network_discovery::kristoffersen_feb18_build(&self.cfg, self.scenario_seed, &self.params)
            }
        }
    }
}

/// Factory returning a configured builder.
pub fn kristoffersen_feb18_scenario_builder(
    cfg: &TelemetryConfig,
    scenario_id: ScenarioId,
    params: ScenarioParams,
) -> Result<ScenarioBuilder, TimelineBuildError> {
    Ok(ScenarioBuilder::new(cfg, scenario_id, params))
}
