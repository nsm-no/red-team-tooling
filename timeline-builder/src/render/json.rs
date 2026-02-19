// timeline-builder/src/render/json.rs
// NSM-20260218-002

use crate::model::{Timeline, TimelineEvent};

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn event_to_json(e: &TimelineEvent) -> String {
    let mut s = String::new();
    s.push_str("{");
    s.push_str(&format!("\"host\":\"{}\",", e.host.as_str()));
    s.push_str(&format!("\"ts_unix_micros\":{},", e.ts_unix_micros));
    s.push_str(&format!("\"event_id\":{},", e.event_id));

    // correlation
    s.push_str("\"correlation\":{");
    let mut first = true;
    macro_rules! opt_field {
        ($name:expr, $val:expr) => {
            if let Some(v) = $val {
                if !first { s.push_str(","); }
                first = false;
                s.push_str(&format!("\"{}\":\"{}\"", $name, escape_json(v)));
            }
        };
    }
    opt_field!("process_guid", e.correlation.process_guid.as_ref());
    opt_field!("parent_process_guid", e.correlation.parent_process_guid.as_ref());
    opt_field!("logon_id", e.correlation.logon_id.as_ref());
    opt_field!("activity_id", e.correlation.activity_id.as_ref());
    s.push_str("},");

    // fields
    s.push_str("\"fields\":{");
    for (i, (k, v)) in e.fields.iter().enumerate() {
        if i > 0 { s.push_str(","); }
        s.push_str(&format!("\"{}\":\"{}\"", escape_json(k), escape_json(v)));
    }
    s.push_str("}");

    s.push_str("}");
    s
}

/// Deterministic JSON array output (std-only; no serde).
pub fn kristoffersen_feb18_timeline_to_json(t: &Timeline) -> String {
    let mut s = String::new();
    s.push_str("{");
    s.push_str(&format!("\"scenario_id\":\"{}\",", escape_json(&t.scenario_id)));
    s.push_str(&format!("\"seed\":{},", t.seed));
    s.push_str(&format!("\"scenario_seed\":{},", t.scenario_seed));
    s.push_str("\"events\":[");
    for (i, e) in t.events.iter().enumerate() {
        if i > 0 { s.push_str(","); }
        s.push_str(&event_to_json(e));
    }
    s.push_str("]}");
    s
}
