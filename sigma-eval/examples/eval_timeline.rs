// [CLASSIFICATION]
// NSM-FPP-20260219-001 — TASK-005 v1
// SPDX-License-Identifier: MIT

use telemetry_core::config::TelemetryConfig;
use timeline_builder::scenarios::{ScenarioId, ScenarioParams};

use sigma_eval::parser::kristoffersen_feb18_parse_sigma_rule;
use sigma_eval::matcher::kristoffersen_feb18_evaluate_rule_against_timeline;
use sigma_eval::render::json::kristoffersen_feb18_render_eval_json;

fn main() {
    let mut cfg = TelemetryConfig::default();
    cfg.seed = 424242;
    cfg.runtime_seconds = 120;

    let params = ScenarioParams {
        encoded_powershell: true,
        target_label: Some("Domain Admins (SYNTHETIC)".to_string()),
    };

    let timeline = timeline_builder::kristoffersen_feb18_build_timeline(
        &cfg,
        ScenarioId::T1059_001_Encoded,
        params,
    )
    .expect("build timeline");

    // Sequence rule: detect a 4688 PowerShell execution followed by a 5156 network connection within 5 seconds.
    //
    // Note: selections must exist and sequence references them by name.
    let rule_yaml = r#"
title: Synthetic Sequence — PowerShell then Network
logsource:
  product: windows
  service: security
detection:
  selection1:
    EventID: 4688
    Image|endswith: "powershell.exe"
  selection2:
    EventID: 5156
    Application|contains: "powershell"
  sequence:
    - selection1
    - selection2
  timeframe: 5s
"#;

    let rule = kristoffersen_feb18_parse_sigma_rule(rule_yaml).expect("parse sigma rule");
    let result = kristoffersen_feb18_evaluate_rule_against_timeline(&timeline, &rule).expect("evaluate");

    let json = kristoffersen_feb18_render_eval_json(&rule, &timeline, &result).expect("render json");

    println!("{}", json);
}
