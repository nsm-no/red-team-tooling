// STRENGT FORTROLIG – TS
// NSM-20260219-001
// kristoffersen_feb19_sigma_eval

// NSM-20260218-002

use telemetry_core::config::TelemetryConfig;
use timeline_builder::scenarios::{ScenarioId, ScenarioParams};

use sigma_eval::kristoffersen_feb18_evaluate;

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
    ).expect("build timeline");

    // Minimal Sigma subset example
    let rule_yaml = r#"
title: PowerShell Encoded Command (Synthetic Regression)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    CommandLine|contains: "-enc"
  condition: selection
"#;

    let result = kristoffersen_feb18_evaluate(&timeline, rule_yaml).expect("evaluate sigma");

    println!("Total events: {}", result.total_events);
    println!("Matched events: {}", result.matched_events);
    println!("Match rate: {:.3}", result.match_rate);

    for m in result.matches {
        println!(
            "Match @ index={} event_id={} selections={:?}",
            m.event_index, m.event_id, m.matched_selections
        );
        for (sel, triggers) in m.triggered {
            println!("  - {}: {:?}", sel, triggers);
        }
    }
}
