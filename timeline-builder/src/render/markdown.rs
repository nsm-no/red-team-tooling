// timeline-builder/src/render/markdown.rs
// NSM-20260218-002

use crate::model::Timeline;

pub fn kristoffersen_feb18_timeline_to_markdown(t: &Timeline) -> String {
    let mut s = String::new();
    s.push_str("# Synthetic Timeline Summary\n\n");
    s.push_str(&format!("- Scenario: `{}`\n", t.scenario_id));
    s.push_str(&format!("- Seed: `{}`\n", t.seed));
    s.push_str(&format!("- Scenario seed: `{}`\n\n", t.scenario_seed));

    s.push_str("| # | ts_unix_micros | host | event_id | process_guid | logon_id | key_fields |\n");
    s.push_str("|---:|---:|---|---:|---|---|---|\n");

    for (i, e) in t.events.iter().enumerate() {
        let pg = e.correlation.process_guid.as_deref().unwrap_or("-");
        let lid = e.correlation.logon_id.as_deref().unwrap_or("-");
        let mut key = String::new();
        for (k, v) in e.fields.iter().take(2) {
            if !key.is_empty() { key.push_str("; "); }
            key.push_str(k);
            key.push('=');
            key.push_str(v);
        }
        s.push_str(&format!(
            "| {} | {} | {} | {} | `{}` | `{}` | {} |\n",
            i + 1,
            e.ts_unix_micros,
            e.host.as_str(),
            e.event_id,
            pg,
            lid,
            key.replace('|', "\\|")
        ));
    }

    s
}
