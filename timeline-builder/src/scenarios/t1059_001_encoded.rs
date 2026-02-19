// timeline-builder/src/scenarios/t1059_001_encoded.rs
// NSM-20260218-002

use telemetry_core::config::TelemetryConfig;

use crate::correlate::{kristoffersen_feb18_guid, kristoffersen_feb18_hex64, Sequence};
use crate::model::{Correlation, HostId, Timeline, TimelineBuildError, TimelineEvent};
use crate::time::MonotonicClock;

use super::ScenarioParams;

/// Telemetry narrative only: encoded PowerShell + correlated script block + correlated network + registry/object access.
pub fn kristoffersen_feb18_build(
    cfg: &TelemetryConfig,
    scenario_seed: u64,
    params: &ScenarioParams,
) -> Result<Timeline, TimelineBuildError> {
    let mut clock = MonotonicClock::new(scenario_seed);
    let mut seq = Sequence::new(scenario_seed ^ 0x1111_2222_3333_4444);

    let scenario_id = "T1059.001_Encoded_20260218".to_string();
    let host = HostId::WorkstationA;

    // Correlation anchors
    let logon_id = kristoffersen_feb18_hex64(scenario_seed, "HOST-A:logon:1");
    let activity_id = kristoffersen_feb18_guid(scenario_seed, "HOST-A:activity:ps");

    // Process GUIDs
    let pg_explorer = kristoffersen_feb18_guid(scenario_seed, &seq.next_label("HOST-A:proc:explorer"));
    let pg_powershell = kristoffersen_feb18_guid(scenario_seed, &seq.next_label("HOST-A:proc:powershell"));
    let pg_child = kristoffersen_feb18_guid(scenario_seed, &seq.next_label("HOST-A:proc:child"));

    let mut events = Vec::<TimelineEvent>::new();

    // 4624 logon
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
            ("LogonType".into(), "3".into()),
            ("AccountName".into(), "USER_X".into()),
            ("WorkstationName".into(), host.as_str().into()),
        ],
    });

    // 4688 explorer baseline (synthetic)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(180, 900),
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

    // 4688 powershell child
    let ps_cmd = if params.encoded_powershell {
        "powershell.exe -enc <SYNTHETIC_BASE64>"
    } else {
        "powershell.exe -NoProfile -Command <SYNTHETIC>"
    };

    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(240, 2000),
        event_id: 4688,
        correlation: Correlation {
            process_guid: Some(pg_powershell.clone()),
            parent_process_guid: Some(pg_explorer.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Image".into(), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into()),
            ("CommandLine".into(), ps_cmd.into()),
            ("ParentImage".into(), "C:\\Windows\\explorer.exe".into()),
        ],
    });

    // 4104 script block (benign enumeration narrative; no operational details)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(140, 2000),
        event_id: 4104,
        correlation: Correlation {
            process_guid: Some(pg_powershell.clone()),
            parent_process_guid: Some(pg_explorer.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("ScriptBlockText".into(), "Get-LocalGroupMember -Group 'Administrators'  # SYNTHETIC".into()),
            ("EngineVersion".into(), "5.1".into()),
        ],
    });

    // 5156 outbound connection to lab-only HTTP listener (fields are synthetic)
    let dst_port: u16 = if let Some(net) = &cfg.network {
    net.http_port
    } else {
            8080
    };

    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(310, 2500),
        event_id: 5156,
        correlation: Correlation {
            process_guid: Some(pg_powershell.clone()),
            parent_process_guid: Some(pg_explorer.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Application".into(), "powershell.exe".into()),
            ("Protocol".into(), "TCP".into()),
            ("DestAddress".into(), dst_ip),
            ("DestPort".into(), dst_port.to_string()),
            ("Action".into(), "ALLOW".into()),
        ],
    });

    // 5158 listen/bind (synthetic, lab narrative)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(180, 2500),
        event_id: 5158,
        correlation: Correlation {
            process_guid: Some(pg_powershell.clone()),
            parent_process_guid: Some(pg_explorer.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Application".into(), "powershell.exe".into()),
            ("Protocol".into(), "TCP".into()),
            ("LocalAddress".into(), "0.0.0.0".into()),
            ("LocalPort".into(), "0".into()),
            ("Action".into(), "ALLOW".into()),
        ],
    });

    // 4657 registry value set (synthetic benign key)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(220, 1500),
        event_id: 4657,
        correlation: Correlation {
            process_guid: Some(pg_powershell.clone()),
            parent_process_guid: Some(pg_explorer.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("ObjectName".into(), "HKCU\\Software\\Lab\\Telemetry".into()),
            ("ValueName".into(), "Scenario".into()),
            ("Value".into(), "T1059.001_SYNTHETIC".into()),
        ],
    });

    // 4663 object access (synthetic file path)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(160, 1500),
        event_id: 4663,
        correlation: Correlation {
            process_guid: Some(pg_powershell.clone()),
            parent_process_guid: Some(pg_explorer.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("ObjectName".into(), "C:\\Lab\\Artifacts\\telemetry.txt".into()),
            ("AccessMask".into(), "0x1".into()),
        ],
    });

    // 4688 child process from PowerShell (synthetic benign)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(260, 2000),
        event_id: 4688,
        correlation: Correlation {
            process_guid: Some(pg_child.clone()),
            parent_process_guid: Some(pg_powershell.clone()),
            logon_id: Some(logon_id.clone()),
            activity_id: Some(activity_id.clone()),
        },
        fields: vec![
            ("Image".into(), "C:\\Lab\\bin\\tool_sim.exe".into()),
            ("CommandLine".into(), "tool_sim.exe --mode telemetry_only".into()),
            ("ParentImage".into(), "powershell.exe".into()),
        ],
    });

    // 4648 explicit credentials (synthetic narrative)
    events.push(TimelineEvent {
        host,
        ts_unix_micros: clock.step(300, 2500),
        event_id: 4648,
        correlation: Correlation {
            process_guid: Some(pg_child),
            parent_process_guid: Some(pg_powershell),
            logon_id: Some(logon_id),
            activity_id: Some(activity_id),
        },
        fields: vec![
            ("TargetServerName".into(), "HOST-DC1".into()),
            ("TargetUserName".into(), "USER_Y".into()),
            ("ProcessName".into(), "C:\\Lab\\bin\\tool_sim.exe".into()),
        ],
    });

    Ok(Timeline {
        scenario_id,
        seed: cfg.seed,
        scenario_seed,
        events,
    })
}
