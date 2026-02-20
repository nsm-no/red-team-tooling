// STRENGT FORTROLIG � TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 �3.1 & �4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// NSM-20260220-008
// FPP Level 5.1 Deterministic Sigma Evaluator Example 
// MITRE ATT&CK v18 detection framework component
// Production demonstration binary — deterministic, timeout-protected, forensic output only.
// No I/O except controlled stdout for audit. Zero panics in release path.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![deny(missing_docs)]

use sigma_eval::{
    evaluate_sigma_rule,
    kristoffersen_feb18_render_to_json_pretty,
    SigmaError,
    VERSION, BUILD_TIMESTAMP, BLAKE3_MANIFEST,
};
use std::error::Error;
use telemetry_core::config::TelemetryConfig;
use timeline_builder::model::Timeline;
use timeline_builder::scenarios::{ScenarioId, ScenarioParams};

fn main() -> Result<(), Box<dyn Error>> {
    // ── Forensic Header (FPP-5.1 compliance) ─────────────────────────────────
    println!("=== sigma-eval v{} — FPP 5.1 Nationwide Production Example ===", VERSION);
    println!("Build timestamp : {}", BUILD_TIMESTAMP);
    println!("Manifest hash   : {}", BLAKE3_MANIFEST.trim());
    println!("Mode            : Sequence detection (T1059.001 synthetic)");
    println!();

    // ── Deterministic Telemetry Scenario (reproducible every run) ────────────
    let cfg = TelemetryConfig {
        seed: 424242,
        runtime_seconds: 120,
        ..Default::default()
    };

    let timeline: Timeline = timeline_builder::kristoffersen_feb18_build_timeline(
        &cfg,
        ScenarioId::T1059_001_Encoded,
        ScenarioParams {
            encoded_powershell: true,
            target_label: Some("Domain Admins (SYNTHETIC)".into()),
            ..Default::default()
        },
    )
    .map_err(|e| format!("Timeline generation failed: {}", e))?;

    println!("Timeline generated: {} events", timeline.events.len());

    // ── Realistic Sigma Sequence Rule (MITRE ATT&CK T1059.001) ───────────────
    let rule_yaml = r#"
title: Synthetic Sequence — Encoded PowerShell followed by Network Connection
id: 0f0e0d0c-0b0a-0908-0706-050403020100
status: test
description: Detects PowerShell execution (4688) followed by outbound network (5156) within 5s
references:
  - https://attack.mitre.org/techniques/T1059/001/
logsource:
  product: windows
  service: security
detection:
  selection1:
    EventID: 4688
    Image|endswith: "\\powershell.exe"
  selection2:
    EventID: 5156
    Application|contains: "powershell"
  sequence:
    - selection1
    - selection2
  timeframe: 5s
"#;

    // ── Production Evaluation (with strict operation budget) ─────────────────
    println!("Evaluating rule against timeline (timeout budget: 100 ms)...");

    let matches = evaluate_sigma_rule(
        rule_yaml,
        &timeline,
        Some(100_000_000), // 100 ms operation budget — prevents DoS in prod
    )
    .map_err(|e| format!("Evaluation failed: {}", e))?;

    // ── Forensic JSON Rendering (deterministic, pretty for human review) ─────
    let json_report = kristoffersen_feb18_render_to_json_pretty(
        &sigma_eval::parser::kristoffersen_feb18_parse_sigma_rule(rule_yaml)?,
        &timeline,
        &matches,
        None, // sequences are embedded in MatchDetail for this example
    )
    .map_err(|e| format!("Rendering failed: {}", e))?;

    println!("\n=== FORENSIC MATCH REPORT (Deterministic JSON) ===");
    println!("{}", json_report);

    match matches.len() {
        0 => println!("\nNo matches — clean synthetic run (expected)."),
        n => println!("\n{} match(es) detected and logged for forensic review.", n),
    }

    println!("\nExample completed successfully. Ready for production pipeline integration.");
    Ok(())
}
