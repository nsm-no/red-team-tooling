// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// timeline-builder/examples/build_timeline.rs
// NSM-20260218-002

use telemetry_core::config::TelemetryConfig;
use timeline_builder::scenarios::{ScenarioId, ScenarioParams};
use timeline_builder::render::{json, xml, markdown};

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

    let out_json = json::kristoffersen_feb18_timeline_to_json(&timeline);
    let out_xml = xml::kristoffersen_feb18_timeline_to_evtx_style_xml(&timeline);
    let out_md = markdown::kristoffersen_feb18_timeline_to_markdown(&timeline);

    println!("--- JSON ---\n{}\n", out_json);
    println!("--- XML ---\n{}\n", out_xml);
    println!("--- MARKDOWN ---\n{}\n", out_md);
}

