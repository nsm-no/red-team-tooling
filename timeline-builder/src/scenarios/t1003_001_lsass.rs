// timeline-builder/src/scenarios/t1003_001_lsass.rs
// NSM-20260218-002

use telemetry_core::config::TelemetryConfig;

use crate::correlate::{kristoffersen_feb18_guid, kristoffersen_feb18_hex64, Sequence};
use crate::model::{Correlation, HostId, Timeline, TimelineBuildError, TimelineEvent};
use crate::time::MonotonicClock;

use super::ScenarioParams;

/// Telemetry narrative only: “sensitive process access” shape.
/// No dumping instructions, no real tooling; uses clearly synthetic placeholders.
pub fn kristoffersen_feb18_build(
    cfg: &TelemetryConfig,
    scenario_seed: u64,
    _params: &ScenarioParams,
) -> Result<Timeline, TimelineBuildError> {
    let mut clock = MonotonicClock::new(scenario_seed);
    let mut seq = Sequence::new(scenario_seed ^ 0xAAAA_BBBB_CCCC_DDDD);

    let scenario_id = "T1003.001_LSASS_TelemetryNarrative_20260218".to_string();
    let host = HostId::ServerB;

    let logon_id = kristoffersen_feb18_hex64(scenario_seed, "HOST-B:logon:1");
    let activity_id = kristoffersen_feb18_guid(scenario_seed, "HOST-B:activity:sensitive-access");

    let pg_services = kristoffersen_feb18_guid(scenario_seed, &seq.next_label("HOST-B:proc:services"));
    let pg_tool = kristoffersen_feb18_guid(scenario_seed, &seq.next_label("HOST-B:proc:tool_sim"));
    let pg_target = kristoffersen_feb18_guid(scenario_seed, &seq.next_label("HOST-B:proc:lsass"));

    let mut events = Vec::<TimelineEvent>::new();

    // 4624 logon (synthetic)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(140, 1200),
        event_id: 4624,
        correlation: Correlation {
            process_guid: None,
            parent_process_guid: None,
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("LogonType".into(), "3".into()),
            ("AccountName".into(), "USER_X".into()),
            ("WorkstationName".into(), host.as_str().into()),
        ],
    });

    // 4688 services.exe baseline
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(180, 1200),
        event_id: 4688,
        correlation: Correlation {
            process_guid: Some(pg_services.clone()),
            parent_process_guid: None,
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Image".into(), "C:\\Windows\\System32\\services.exe".into()),
            ("CommandLine".into(), "services.exe".into()),
        ],
    });

    // 4688 lsass.exe (synthetic anchor for correlation; not executed)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(220, 1200),
        event_id: 4688,
        correlation: Correlation {
            process_guid: Some(pg_target.clone()),
            parent_process_guid: Some(pg_services.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Image".into(), "C:\\Windows\\System32\\lsass.exe".into()),
            ("CommandLine".into(), "lsass.exe  # SYNTHETIC_ANCHOR".into()),
            ("ParentImage".into(), "services.exe".into()),
        ],
    });

    // 4688 tool_sim.exe starts (synthetic)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(300, 2200),
        event_id: 4688,
        correlation: Correlation {
            process_guid: Some(pg_tool.clone()),
            parent_process_guid: Some(pg_services.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Image".into(), "C:\\Lab\\bin\\tool_sim.exe".into()),
            ("CommandLine".into(), "tool_sim.exe --mode telemetry_only --target sensitive_process".into()),
            ("ParentImage".into(), "services.exe".into()),
        ],
    });

    // 4663 object access referencing sensitive target (synthetic)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(220, 1500),
        event_id: 4663,
        correlation: Correlation {
            process_guid: Some(pg_tool.clone()),
            parent_process_guid: Some(pg_services.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("ObjectName".into(), "PROCESS:lsass.exe  # SYNTHETIC".into()),
            ("AccessMask".into(), "0x1410".into()),
            ("Note".into(), "Synthetic sensitive-process access telemetry".into()),
        ],
    });

    // 4657 registry set (benign lab tag)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(180, 1500),
        event_id: 4657,
        correlation: Correlation {
            process_guid: Some(pg_tool.clone()),
            parent_process_guid: Some(pg_services.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("ObjectName".into(), "HKLM\\Software\\Lab\\Telemetry".into()),
            ("ValueName".into(), "SensitiveAccessScenario".into()),
            ("Value".into(), "T1003.001_SYNTHETIC".into()),
        ],
    });

    // 5156 network (lab-only) - represents telemetry correlation, not exfiltration
    let (dst_ip, dst_port) = if let Some(net) = &cfg.network {
        (net.http_target_ip.clone(), net.http_port)
    } else {
        ("127.0.0.1".to_string(), 8080)
    };

    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(260, 2000),
        event_id: 5156,
        correlation: Correlation {
            process_guid: Some(pg_tool.clone()),
            parent_process_guid: Some(pg_services.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Application".into(), "tool_sim.exe".into()),
            ("Protocol".into(), "TCP".into()),
            ("DestAddress".into(), dst_ip),
            ("DestPort".into(), dst_port.to_string()),
            ("Action".into(), "ALLOW".into()),
            ("Note".into(), "Synthetic outbound telemetry".into()),
        ],
    });

    // Add a few more correlated events to exceed 10 total
    for i in 0..4 {
        events.push(TimelineEvent {
            host,
            ts_unix_micros: clock.step(140 + (i * 40), 1200),
            event_id: 4104,
            correlation: Correlation {
                process_guid: Some(pg_tool.clone()),
                parent_process_guid: Some(pg_services.clone()),
                logon_id: Some(logon_id.clone()),
                activity_id: Some(activity_id.clone()),
            },
            fields: vec![
                ("ScriptBlockText".into(), format!("Write-Output \"SYNTHETIC_STEP_{}\"", i + 1)),
                ("EngineVersion".into(), "5.1".into()),
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
