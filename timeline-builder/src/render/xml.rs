// timeline-builder/src/render/xml.rs
// NSM-20260218-002

use crate::model::{Timeline, TimelineEvent};

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Very simple Unix-micros to RFC3339 UTC conversion (std-only).
/// This is deterministic and sufficient for synthetic logs.
/// (Implements a civil-from-days conversion.)
fn unix_micros_to_rfc3339(micros: i64) -> String {
    let mut secs = micros / 1_000_000;
    let us = (micros % 1_000_000).abs();

    // Handle negative just in case
    if secs < 0 {
        secs = 0;
    }

    let days = secs / 86_400;
    let sod = (secs % 86_400) as i64;

    // Civil-from-days (Howard Hinnant algorithm)
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };

    let hour = sod / 3600;
    let min = (sod % 3600) / 60;
    let sec = sod % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        year, m, d, hour, min, sec, us
    )
}

fn event_to_xml(e: &TimelineEvent) -> String {
    let ts = unix_micros_to_rfc3339(e.ts_unix_micros);
    let mut s = String::new();
    s.push_str("<Event>");
    s.push_str("<System>");
    s.push_str(&format!("<EventID>{}</EventID>", e.event_id));
    s.push_str(&format!("<Computer>{}</Computer>", e.host.as_str()));
    s.push_str(&format!("<TimeCreated SystemTime=\"{}\"/>", ts));
    s.push_str("</System>");
    s.push_str("<EventData>");

    // Correlation as explicit Data fields
    if let Some(v) = &e.correlation.process_guid {
        s.push_str(&format!(
            "<Data Name=\"ProcessGuid\">{}</Data>",
            xml_escape(v)
        ));
    }
    if let Some(v) = &e.correlation.parent_process_guid {
        s.push_str(&format!(
            "<Data Name=\"ParentProcessGuid\">{}</Data>",
            xml_escape(v)
        ));
    }
    if let Some(v) = &e.correlation.logon_id {
        s.push_str(&format!(
            "<Data Name=\"LogonId\">{}</Data>",
            xml_escape(v)
        ));
    }
    if let Some(v) = &e.correlation.activity_id {
        s.push_str(&format!(
            "<Data Name=\"ActivityId\">{}</Data>",
            xml_escape(v)
        ));
    }

    for (k, v) in &e.fields {
        s.push_str(&format!(
            "<Data Name=\"{}\">{}</Data>",
            xml_escape(k),
            xml_escape(v)
        ));
    }

    s.push_str("</EventData>");
    s.push_str("</Event>");
    s
}

/// EVTX-style XML (not binary EVTX).
pub fn kristoffersen_feb18_timeline_to_evtx_style_xml(t: &Timeline) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
    s.push_str("<Events>");
    // Header metadata as comment (explicit provenance)
    s.push_str(&format!(
        "<!-- scenario_id={} seed={} scenario_seed={} -->",
        xml_escape(&t.scenario_id),
        t.seed,
        t.scenario_seed
    ));
    for e in &t.events {
        s.push_str(&event_to_xml(e));
    }
    s.push_str("</Events>");
    s
}
