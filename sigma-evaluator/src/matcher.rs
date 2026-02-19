// STRENGT FORTROLIG � TS
// NSM-20260219-001
// kristoffersen_feb19_sigma_eval

// NSM-20260218-002

use crate::parser::{Detection, FieldMatcher, MatchOp, SigmaRule};
use timeline_builder::model::{Timeline, TimelineEvent};

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct MatchDetail {
    pub event_index: usize,
    pub event_id: u32,
    /// Selections referenced in the condition that evaluated to true for this event.
    pub matched_selections: Vec<String>,
    /// конкрет field triggers (selection -> list of "Field op Value" strings)
    pub triggered: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct EvalResult {
    pub total_events: usize,
    pub matched_events: usize,
    pub match_rate: f64,
    pub matches: Vec<MatchDetail>,
}

/// Evaluate a parsed SigmaRule against a timeline.
pub fn kristoffersen_feb18_evaluate_rule_against_timeline(
    timeline: &Timeline,
    rule: &SigmaRule,
) -> Result<EvalResult, String> {
    let det = &rule.detection;

    // Pre-parse condition expression into RPN for deterministic evaluation.
    let rpn = kristoffersen_feb18_condition_to_rpn(&det.condition, det)?;

    let mut matches: Vec<MatchDetail> = Vec::new();

    for (idx, ev) in timeline.events.iter().enumerate() {
        let (is_match, sel_results, triggered) =
            evaluate_event_against_detection(ev, det, &rpn)?;

        if is_match {
            let mut matched_selections: Vec<String> = sel_results
                .iter()
                .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
                .collect();
            matched_selections.sort();

            matches.push(MatchDetail {
                event_index: idx,
                event_id: ev.event_id,
                matched_selections,
                triggered,
            });
        }
    }

    let total = timeline.events.len();
    let matched = matches.len();
    let rate = if total == 0 { 0.0 } else { matched as f64 / total as f64 };

    Ok(EvalResult {
        total_events: total,
        matched_events: matched,
        match_rate: rate,
        matches,
    })
}

fn evaluate_event_against_detection(
    ev: &TimelineEvent,
    det: &Detection,
    rpn: &[CondToken],
) -> Result<(bool, BTreeMap<String, bool>, BTreeMap<String, Vec<String>>), String> {
    // Evaluate each selection first
    let mut sel_results: BTreeMap<String, bool> = BTreeMap::new();
    let mut triggered: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (name, sel) in det.selections.iter() {
        let (ok, trig) = selection_matches(ev, &sel.matchers);
        sel_results.insert(name.clone(), ok);
        if ok && !trig.is_empty() {
            triggered.insert(name.clone(), trig);
        }
    }

    // Evaluate condition (RPN)
    let mut stack: Vec<bool> = Vec::new();
    for tok in rpn {
        match tok {
            CondToken::Sel(name) => {
                let v = *sel_results.get(name).unwrap_or(&false);
                stack.push(v);
            }
            CondToken::And => {
                let b = stack.pop().ok_or("condition stack underflow (and)")?;
                let a = stack.pop().ok_or("condition stack underflow (and)")?;
                stack.push(a && b);
            }
            CondToken::Or => {
                let b = stack.pop().ok_or("condition stack underflow (or)")?;
                let a = stack.pop().ok_or("condition stack underflow (or)")?;
                stack.push(a || b);
            }
        }
    }

    if stack.len() != 1 {
        return Err("condition evaluation error (stack not singular)".to_string());
    }

    Ok((stack[0], sel_results, triggered))
}

fn selection_matches(ev: &TimelineEvent, matchers: &[FieldMatcher]) -> (bool, Vec<String>) {
    // AND semantics within selection
    let mut triggered: Vec<String> = Vec::new();
    for m in matchers {
        let ok = matcher_matches(ev, m);
        if !ok {
            return (false, Vec::new());
        }
        triggered.push(format!("{} {:?} {}", m.field, m.op, m.value));
    }
    (true, triggered)
}

fn matcher_matches(ev: &TimelineEvent, m: &FieldMatcher) -> bool {
    let field = m.field.as_str();

    // Normalize both sides to lower for case-insensitive comparison (pragmatic for Sigma)
    let want = m.value.to_lowercase();

    // Special built-ins
    if field.eq_ignore_ascii_case("EventID") {
        return match m.op {
            MatchOp::Equals => ev.event_id.to_string() == m.value,
            MatchOp::Contains => ev.event_id.to_string().contains(&m.value),
        };
    }

    if field.eq_ignore_ascii_case("Computer") || field.eq_ignore_ascii_case("Host") {
        let got = ev.host.as_str().to_lowercase();
        return match m.op {
            MatchOp::Equals => got == want,
            MatchOp::Contains => got.contains(&want),
        };
    }

    // Look up in EventData fields
    let got_opt = ev
        .fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(field))
        .map(|(_, v)| v);

    let got = match got_opt {
        Some(v) => v.to_lowercase(),
        None => return false,
    };

    match m.op {
        MatchOp::Equals => got == want,
        MatchOp::Contains => got.contains(&want),
    }
}

/* ---------------- Condition parsing (and/or + parentheses) ---------------- */

#[derive(Debug, Clone)]
enum CondToken {
    Sel(String),
    And,
    Or,
}

/// Tokenize condition into identifiers/operators/parens.
fn tokenize_condition(cond: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();

    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            out.push(cur.clone());
            cur.clear();
        }
    };

    for ch in cond.chars() {
        match ch {
            '(' | ')' => {
                flush(&mut cur, &mut out);
                out.push(ch.to_string());
            }
            ' ' | '\t' | '\n' | '\r' => {
                flush(&mut cur, &mut out);
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Convert condition to Reverse Polish Notation (Shunting-yard).
pub fn kristoffersen_feb18_condition_to_rpn(
    cond: &str,
    det: &Detection,
) -> Result<Vec<CondToken>, String> {
    let toks = tokenize_condition(cond);

    // Valid selections set (for deterministic validation)
    let valid: BTreeSet<String> = det.selections.keys().cloned().collect();

    let mut out: Vec<CondToken> = Vec::new();
    let mut ops: Vec<String> = Vec::new();

    fn prec(op: &str) -> i32 {
        match op {
            "and" => 2,
            "or" => 1,
            _ => 0,
        }
    }

    for t in toks {
        let tl = t.to_lowercase();
        match tl.as_str() {
            "and" | "or" => {
                while let Some(top) = ops.last() {
                    if top == "(" {
                        break;
                    }
                    if prec(top) >= prec(&tl) {
                        let top = ops.pop().unwrap();
                        out.push(match top.as_str() {
                            "and" => CondToken::And,
                            "or" => CondToken::Or,
                            _ => return Err(format!("unknown operator {}", top)),
                        });
                    } else {
                        break;
                    }
                }
                ops.push(tl);
            }
            "(" => ops.push("(".to_string()),
            ")" => {
                while let Some(top) = ops.pop() {
                    if top == "(" {
                        break;
                    }
                    out.push(match top.as_str() {
                        "and" => CondToken::And,
                        "or" => CondToken::Or,
                        _ => return Err(format!("unknown operator {}", top)),
                    });
                }
            }
            _ => {
                // selection identifier
                if !valid.contains(&t) {
                    return Err(format!(
                        "condition references unknown selection identifier: {}",
                        t
                    ));
                }
                out.push(CondToken::Sel(t));
            }
        }
    }

    while let Some(top) = ops.pop() {
        if top == "(" {
            return Err("unbalanced parentheses in condition".to_string());
        }
        out.push(match top.as_str() {
            "and" => CondToken::And,
            "or" => CondToken::Or,
            _ => return Err(format!("unknown operator {}", top)),
        });
    }

    Ok(out)
}

/* ---------------- Optional timeline JSON parsing ---------------- */

#[derive(Debug, Deserialize)]
struct TimelineJson {
    scenario_id: String,
    seed: u64,
    scenario_seed: u64,
    events: Vec<EventJson>,
}

#[derive(Debug, Deserialize)]
struct EventJson {
    host: String,
    ts_unix_micros: i64,
    event_id: u32,
    correlation: CorrelationJson,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct CorrelationJson {
    process_guid: Option<String>,
    parent_process_guid: Option<String>,
    logon_id: Option<String>,
    activity_id: Option<String>,
}

/// Parse JSON string produced by `timeline-builder` renderer into `timeline_builder::model::Timeline`.
///
/// NOTE: Your `timeline-builder` JSON renderer is hand-rolled; ensure the field shapes match.
/// If you keep evaluation on `Timeline` objects, you can skip this entirely.
pub fn kristoffersen_feb18_parse_timeline_json(json: &str) -> Result<Timeline, String> {
    let tj: TimelineJson = serde_json::from_str(json).map_err(|e| e.to_string())?;

    let mut events: Vec<TimelineEvent> = Vec::with_capacity(tj.events.len());
    for e in tj.events {
        let host = match e.host.as_str() {
            "HOST-A" => timeline_builder::model::HostId::WorkstationA,
            "HOST-B" => timeline_builder::model::HostId::ServerB,
            "HOST-DC1" => timeline_builder::model::HostId::DomainController,
            other => {
                return Err(format!("unknown host in timeline JSON: {}", other));
            }
        };

        let mut fields_vec: Vec<(String, String)> = e.fields.into_iter().collect();
        fields_vec.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic ordering

        events.push(TimelineEvent {
            host,
            ts_unix_micros: e.ts_unix_micros,
            event_id: e.event_id,
            correlation: timeline_builder::model::Correlation {
                process_guid: e.correlation.process_guid,
                parent_process_guid: e.correlation.parent_process_guid,
                logon_id: e.correlation.logon_id,
                activity_id: e.correlation.activity_id,
            },
            fields: fields_vec,
        });
    }

    Ok(Timeline {
        scenario_id: tj.scenario_id,
        seed: tj.seed,
        scenario_seed: tj.scenario_seed,
        events,
    })
}
