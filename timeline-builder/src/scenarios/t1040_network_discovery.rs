// STRENGT FORTROLIG ñ TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 ß3.1 & ß4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// timeline-builder/src/scenarios/t1040_network_discovery.rs
// NSM-20260218-002

use telemetry_core::config::TelemetryConfig;

use crate::correlate::{kristoffersen_feb18_guid, kristoffersen_feb18_hex64, Sequence};
use crate::model::{Correlation, HostId, Timeline, TimelineBuildError, TimelineEvent};
use crate::time::MonotonicClock;

use super::ScenarioParams;

/// Telemetry narrative only: multiple internal connection attempts represented as firewall events.
/// No scanning logic; just synthetic connection telemetry.
pub fn kristoffersen_feb18_build(
    cfg: &TelemetryConfig,
    scenario_seed: u64,
    params: &ScenarioParams,
) -> Result<Timeline, TimelineBuildError> {
    let mut clock = MonotonicClock::new(scenario_seed);
    let mut seq = Sequence::new(scenario_seed ^ 0x0F0F_0A0A_1234_4321);

    let scenario_id = "T1040_NetworkDiscovery_20260218".to_string();
    let host = HostId::WorkstationA;

    let logon_id = kristoffersen_feb18_hex64(scenario_seed, "HOST-A:logon:net:1");
    let activity_id = kristoffersen_feb18_guid(scenario_seed, "HOST-A:activity:net");

    let pg_explorer = kristoffersen_feb18_guid(scenario_seed, &seq.next_label("HOST-A:proc:explorer"));
    let pg_tool = kristoffersen_feb18_guid(scenario_seed, &seq.next_label("HOST-A:proc:net_tool_sim"));

    let mut events = Vec::<TimelineEvent>::new();

    // 4624
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(120, 900),
        event_id: 4624,
        correlation: Correlation {
            process_guid: None,
            parent_process_guid: None,
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("LogonType".into(), "2".into()),
            ("AccountName".into(), "USER_X".into()),
            ("WorkstationName".into(), host.as_str().into()),
        ],
    });

    // 4688 explorer baseline
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(220, 900),
        event_id: 4688,
        correlation: Correlation {
            process_guid: Some(pg_explorer.clone()),
            parent_process_guid: None,
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Image".into(), "C:\\Windows\\explorer.exe".into()),
            ("CommandLine".into(), "explorer.exe".into()),
        ],
    });

    // 4688 tool_sim that ‚Äúenumerates‚Äù (synthetic)
    let label = params.target_label.clone().unwrap_or_else(|| "INTERNAL_SUBNET".to_string());
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(260, 1500),
        event_id: 4688,
        correlation: Correlation {
            process_guid: Some(pg_tool.clone()),
            parent_process_guid: Some(pg_explorer.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Image".into(), "C:\\Lab\\bin\\net_tool_sim.exe".into()),
            ("CommandLine".into(), format!("net_tool_sim.exe --mode telemetry_only --target {}", label)),
            ("ParentImage".into(), "C:\\Windows\\explorer.exe".into()),
        ],
    });

    // Multiple synthetic 5156 connection attempts (lab-only)
    // Determine lab destination base from config (if present), otherwise loopback.
    let base_ip = if let Some(net) = &cfg.network {
        net.http_target_ip.clone()
    } else {
        "127.0.0.1".to_string()
    };

    // Emit 8 connection events (ensures 10+ total events)
    for i in 0..8 {
        events.push(TimelineEvent {
            host,
            ts_unix_micros: clock.step(140, 2500),
            event_id: 5156,
            correlation: Correlation {
                process_guid: Some(pg_tool.clone()),
                parent_process_guid: Some(pg_explorer.clone()),
                logon_id: Some(logon_id.clone()),
                activity_id: Some(activity_id.clone()),
            },
            fields: vec![
                ("Application".into(), "net_tool_sim.exe".into()),
                ("Protocol".into(), "TCP".into()),
                ("DestAddress".into(), base_ip.clone()),
                ("DestPort".into(), (8000 + i).to_string()),
                ("Action".into(), "ALLOW".into()),
                ("Note".into(), "Synthetic internal connection telemetry".into()),
            ],
        });
    }

    Ok(Timeline {
        scenario_id,
        seed: cfg.seed,
        scenario_seed,
        events,
    })
}

