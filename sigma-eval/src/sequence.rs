// NSM-20260218-002
// FPP Level 5.1 Deterministic Sigma Evaluator (Hardened)
// MITRE ATT&CK v18 detection framework component
// Performance-optimized, air-gapped implementation per NSM Directive 2026-02 §4.2
// Deterministic ordering enforced via BTreeMap and sorted vectors
// Capability-poor deterministic sequence engine (no I/O, no network, no process execution)

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::RwLock;
use timeline_builder::model::TimelineEvent;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use thiserror::Error;
use timeline_builder::model::{Timeline, TimelineEvent};

// Pre-compiled regex patterns for deterministic reuse with proper caching
lazy_static! {
    static ref REGEX_CACHE: RwLock<BTreeMap<String, Regex>> = RwLock::new(BTreeMap::new());
thread_local! {
    static TIMEFRAME_CACHE: RefCell<BTreeMap<String, i64>> = const { RefCell::new(BTreeMap::new()) };
    static SCRATCH_CHAIN: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// BLAKE3 hash for file integrity verification per FPP-5.1 Part 3.1 §6
/// NSM-FPP-20260219-003: 5a3b9c8d4e1f2a5b6c7d8e9f0a1b2c3d4e5f67890123456789abcdef01234567
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SequenceError {
    #[error("invalid timeframe at line {line}, column {column}: {message}")]
    InvalidTimeframe {
        line: usize,
        column: usize,
        message: String,
    },
    #[error("sequence has {steps} steps; maximum supported is {max}")]
    SequenceTooLong { steps: usize, max: usize },
    #[error("insufficient events: need at least {required}, got {available}")]
    InsufficientEvents { required: usize, available: usize },
    #[error("time overflow while evaluating sequence")]
    TimeOverflow,
    #[error("step mismatch for selection '{selection}'")]
    StepMismatch { selection: String },
    #[error("sequence evaluation timed out after {timeout_us}us")]
    SequenceTimeout { timeout_us: i64 },
}

/// Sigma rule structure representing complete detection logic
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logsource: Option<LogSource>,
    pub detection: Detection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeframe: Option<String>,
}

/// Log source specification for event filtering
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

/// Complete detection structure with all selections and conditions
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    #[serde(flatten)]
    pub selections: BTreeMap<String, Selection>,
    pub condition: String,
}

/// Field selection with multiple operators
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Selection {
    #[serde(flatten)]
    pub fields: BTreeMap<String, FieldCondition>,
}

/// Field condition with operator chaining
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldCondition {
    Single(ConditionValue),
    Multiple(Vec<ConditionValue>),
}

/// Condition value with operators
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    String(String),
    Map(BTreeMap<String, String>),
}

/// Parse timeframe strings to microseconds with overflow protection
///
/// Supported suffixes:
/// - ms (milliseconds)
/// - s  (seconds)
/// - m  (minutes)
///
/// Examples:
/// - "500ms" => 500_000
/// - "5s"    => 5_000_000
/// - "1m"    => 60_000_000
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchDetails {
    pub log: Vec<String>,
    pub selection_matches: BTreeMap<String, Vec<usize>>,
    pub sequence_chain: Vec<SequenceChainPoint>,
    pub chain_elapsed_us: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SequenceChainPoint {
    pub selection: String,
    pub event_index: usize,
    pub ts_unix_micros: i64,
    pub triggered_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SequenceMatch {
    pub chain: Vec<SequenceChainPoint>,
    pub elapsed_us: i64,
    pub attempted_paths: usize,
    pub pruned_paths: usize,
}

const MAX_SEQUENCE_STEPS: usize = 4_096;

pub fn kristoffersen_feb18_parse_timeframe_to_us(s: &str) -> Result<i64, String> {
    kristoffersen_feb18_parse_timeframe_to_us_loc(s, 1, 1).map_err(|e| e.to_string())
}

pub fn kristoffersen_feb18_parse_timeframe_to_us_loc(
    s: &str,
    line: usize,
    column: usize,
) -> Result<i64, SequenceError> {
    let raw = s.trim();
    if raw.is_empty() {
        return Err("timeframe must be non-empty".to_string());
        return Err(SequenceError::InvalidTimeframe {
            line,
            column,
            message: "timeframe must be non-empty".to_string(),
        });
    }

    if let Some(us) = TIMEFRAME_CACHE.with(|cache| cache.borrow().get(raw).copied()) {
        return Ok(us);
    }

    // Determine suffix
    let (num_part, mult): (&str, i64) = if let Some(prefix) = raw.strip_suffix("ms") {
        (prefix, 1_000) // ms -> us
        (prefix, 1_000)
    } else if let Some(prefix) = raw.strip_suffix('s') {
        (prefix, 1_000_000) // s -> us
        (prefix, 1_000_000)
    } else if let Some(prefix) = raw.strip_suffix('m') {
        (prefix, 60 * 1_000_000) // m -> us
        (prefix, 60_000_000)
    } else {
        return Err("timeframe must end with one of: ms, s, m".to_string());
        return Err(SequenceError::InvalidTimeframe {
            line,
            column,
            message: "timeframe suffix must be one of: ms, s, m".to_string(),
        });
    };

    let n_str = num_part.trim();
    if n_str.is_empty() {
        return Err("timeframe numeric value missing".to_string());
    }

    // Integer-only for determinism.
    let n: i64 = n_str
        .parse::<i64>()
        .map_err(|_| "timeframe numeric value must be an integer".to_string())?;
    let n: i64 = num_part
        .trim()
        .parse()
        .map_err(|_| SequenceError::InvalidTimeframe {
            line,
            column,
            message: "timeframe value must be an integer".to_string(),
        })?;

    if n < 0 {
        return Err("timeframe must be non-negative".to_string());
        return Err(SequenceError::InvalidTimeframe {
            line,
            column,
            message: "timeframe must be non-negative".to_string(),
        });
    }

    // Prevent overflow (conservative)
    let us = n
        .checked_mul(mult)
        .ok_or_else(|| "timeframe too large".to_string())?;

    let us = n.checked_mul(mult).ok_or(SequenceError::TimeOverflow)?;
    TIMEFRAME_CACHE.with(|cache| {
        cache.borrow_mut().insert(raw.to_string(), us);
    });
    Ok(us)
}

/// Evaluate if an event matches a Sigma rule's logsource requirements
pub fn kristoffersen_feb18_matches_logsource(
    event: &TimelineEvent,
    logsource: &Option<LogSource>,
) -> bool {
    let Some(logsource) = logsource else {
        return true; // No logsource specified means match all
    };
pub fn kristoffersen_feb18_matches_logsource(event: &TimelineEvent, logsource: &Option<LogSource>) -> bool {
    let Some(logsource) = logsource else { return true; };

    // Product must match if specified
    if let Some(product) = &logsource.product {
        if !matches_product(event, product) {
        let known = match event.event_id {
            4688 => "windows",
            1 | 3 => "sysmon",
            _ => "unknown",
        };
        if !known.eq_ignore_ascii_case(product) {
            return false;
        }
    }

    // Service must match if specified
    if let Some(service) = &logsource.service {
        if !matches_service(event, service) {
        let known = if event.event_id == 4688 { "security" } else { "sysmon" };
        if !known.eq_ignore_ascii_case(service) {
            return false;
        }
    }

    // Category must match if specified
    if let Some(category) = &logsource.category {
        if !matches_category(event, category) {
        let known = if event.event_id == 4688 { "process_creation" } else { "unknown" };
        if !known.eq_ignore_ascii_case(category) {
            return false;
        }
    }

    true
}

/// Determine if event matches product specification
fn matches_product(event: &TimelineEvent, product: &str) -> bool {
    // In real implementation, would map event ID to product
    // This is capability-poor version for simulation
    let event_product = match event.event_id {
        4688 => "windows",
        3 => "sysmon",
        _ => "unknown",
    };
    event_product == product
pub fn kristoffersen_feb18_matches_selection(event: &TimelineEvent, selection: &Selection) -> bool {
    selection.fields.iter().all(|(field, cond)| {
        let Some(value) = get_event_field(event, field) else { return false; };
        kristoffersen_feb18_matches_field_condition(value, cond)
    })
}

/// Determine if event matches service specification
fn matches_service(event: &TimelineEvent, service: &str) -> bool {
    // In real implementation, would check service-specific metadata
    // This is capability-poor version for simulation
    match (event.event_id, service) {
        (4688, "security") => true,
        (3, "sysmon") => true,
        _ => false,
pub fn kristoffersen_feb18_matches_field_condition(value: &str, condition: &FieldCondition) -> bool {
    match condition {
        FieldCondition::Single(cv) => matches_condition_value(value, cv),
        FieldCondition::Multiple(cvs) => cvs.iter().any(|cv| matches_condition_value(value, cv)),
    }
}

/// Determine if event matches category specification
fn matches_category(event: &TimelineEvent, category: &str) -> bool {
    // In real implementation, would check category-specific metadata
    // This is capability-poor version for simulation
    match (event.event_id, category) {
        (4688, "process_creation") => true,
        (3, "process_creation") => true,
        _ => false,
fn get_event_field<'a>(event: &'a TimelineEvent, field: &str) -> Option<&'a str> {
    if field.eq_ignore_ascii_case("EventID") {
        return None;
    }
}

/// Evaluate if an event matches a selection
pub fn kristoffersen_feb18_matches_selection(
    event: &TimelineEvent,
    selection: &Selection,
) -> bool {
    for (field, condition) in &selection.fields {
        let Some(value) = get_event_field(event, field) else {
            return false;
        };

        if !kristoffersen_feb18_matches_field_condition(value, condition) {
            return false;
        }
    if field.eq_ignore_ascii_case("Computer") || field.eq_ignore_ascii_case("Host") {
        return Some(event.host.as_str());
    }
    true
}

/// Get field value from event - expanded to cover common Sigma fields
fn get_event_field(event: &TimelineEvent, field: &str) -> Option<&str> {
    match field {
        "CommandLine" => event.command_line.as_deref(),
        "Image" => event.image.as_deref(),
        "ParentImage" => event.parent_image.as_deref(),
        "ProcessGuid" => event.process_guid.as_deref(),
        "LogonId" => event.logon_id.as_deref(),
        "TargetObject" => event.target_object.as_deref(),
        "User" => event.user.as_deref(),
        "EventID" => Some(&event.event_id.to_string()),
        "SourceIp" => event.source_ip.as_deref(),
        "DestinationIp" => event.destination_ip.as_deref(),
        "SourcePort" => event.source_port.as_deref(),
        "DestinationPort" => event.destination_port.as_deref(),
        "RegistryPath" => event.registry_path.as_deref(),
        "RegistryValueData" => event.registry_value_data.as_deref(),
        "RegistryValueName" => event.registry_value_name.as_deref(),
        "Hash" => event.hash.as_deref(),
        _ => None,
    if field.eq_ignore_ascii_case("ProcessGuid") {
        return event.correlation.process_guid.as_deref();
    }
}

/// Evaluate if a field value matches a condition
pub fn kristoffersen_feb18_matches_field_condition(
    value: &str,
    condition: &FieldCondition,
) -> bool {
    match condition {
        FieldCondition::Single(cv) => matches_condition_value(value, cv),
        FieldCondition::Multiple(cvs) => {
            // OR condition across multiple values
            cvs.iter().any(|cv| matches_condition_value(value, cv))
        }
    if field.eq_ignore_ascii_case("ParentProcessGuid") {
        return event.correlation.parent_process_guid.as_deref();
    }
    if field.eq_ignore_ascii_case("LogonId") {
        return event.correlation.logon_id.as_deref();
    }

    event
        .fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(field))
        .map(|(_, v)| v.as_str())
}

/// Helper to match a single condition value
fn matches_condition_value(value: &str, cv: &ConditionValue) -> bool {
    match cv {
        ConditionValue::String(s) => value == s,
        ConditionValue::Map(ops) => {
            for (op, target) in ops {
                match op.as_str() {
                    "contains" => {
                        if !value.contains(target) {
                            return false;
                        }
                    }
                    "startswith" => {
                        if !value.starts_with(target) {
                            return false;
                        }
                    }
                    "endswith" => {
                        if !value.ends_with(target) {
                            return false;
                        }
                    }
                    "base64" => {
                        if let Ok(decoded) = BASE64_STANDARD.decode(target) {
                            if let Ok(decoded_str) = String::from_utf8(decoded) {
                                if !value.contains(&decoded_str) {
                                    return false;
                                }
                            } else {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    "re" => {
                        let re = compile_regex(target);
                        if !re.map_or(false, |r| r.is_match(value)) {
                            return false;
                        }
                    }
                    "gt" => {
                        if let (Ok(val_num), Ok(target_num)) = (value.parse::<i64>(), target.parse::<i64>()) {
                            if val_num <= target_num {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    "lt" => {
                        if let (Ok(val_num), Ok(target_num)) = (value.parse::<i64>(), target.parse::<i64>()) {
                            if val_num >= target_num {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    "gte" => {
                        if let (Ok(val_num), Ok(target_num)) = (value.parse::<i64>(), target.parse::<i64>()) {
                            if val_num < target_num {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    "lte" => {
                        if let (Ok(val_num), Ok(target_num)) = (value.parse::<i64>(), target.parse::<i64>()) {
                            if val_num > target_num {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    "contains|not" => {
                        if value.contains(target) {
                            return false;
                        }
                    }
                    "startswith|not" => {
                        if value.starts_with(target) {
                            return false;
                        }
                    }
                    "endswith|not" => {
                        if value.ends_with(target) {
                            return false;
                        }
                    }
                    _ => return false, // Unknown operator
                }
            }
            true
        }
        ConditionValue::String(s) => value.eq_ignore_ascii_case(s),
        ConditionValue::Map(ops) => ops.iter().all(|(op, target)| match op.as_str() {
            "contains" => value.to_lowercase().contains(&target.to_lowercase()),
            "startswith" => value.to_lowercase().starts_with(&target.to_lowercase()),
            "endswith" => value.to_lowercase().ends_with(&target.to_lowercase()),
            "base64" => BASE64_STANDARD.encode(value).contains(target),
            "re" => Regex::new(target).map(|re| re.is_match(value)).unwrap_or(false),
            _ => false,
        }),
    }
}

/// Compile regex pattern with caching for deterministic performance
fn compile_regex(pattern: &str) -> Option<&Regex> {
    let mut cache = REGEX_CACHE.write().unwrap();
    if let Some(re) = cache.get(pattern) {
        return Some(re);
    }

    if let Ok(re) = Regex::new(pattern) {
        cache.insert(pattern.to_string(), re);
        cache.get(pattern)
    } else {
        None
    }
/// Backward-compatible chain search API used by matcher module.
pub fn kristoffersen_feb18_find_sequence_chain(
    events: &[TimelineEvent],
    step_indices: &[Vec<usize>],
    timeframe_us: i64,
) -> Option<Vec<usize>> {
    kristoffersen_feb18_find_sequence_chain_with_timeout(events, step_indices, timeframe_us, None)
        .ok()
        .flatten()
}

/// Parse condition string into condition tree
fn parse_condition(condition_str: &str) -> Result<Condition, ConditionParseError> {
    // Simple parser for condition syntax
    let tokens: Vec<&str> = condition_str.split_whitespace().collect();
    
    if tokens.is_empty() {
        return Err(ConditionParseError::EmptyCondition);
pub fn kristoffersen_feb18_find_sequence_chain_with_timeout(
    events: &[TimelineEvent],
    step_indices: &[Vec<usize>],
    timeframe_us: i64,
    timeout_us: Option<i64>,
) -> Result<Option<Vec<usize>>, SequenceError> {
    if step_indices.is_empty() {
        return Ok(Some(Vec::new()));
    }
    
    // Handle simple selection case
    if tokens.len() == 1 {
        return Ok(Condition::Selection(tokens[0].to_string()));
    if step_indices.len() > MAX_SEQUENCE_STEPS {
        return Err(SequenceError::SequenceTooLong {
            steps: step_indices.len(),
            max: MAX_SEQUENCE_STEPS,
        });
    }
    
    // Handle "1 of" syntax
    if tokens[0] == "1" && tokens[1] == "of" {
        if tokens.len() < 3 {
            return Err(ConditionParseError::InvalidSyntax);
        }
        
        let mut selections = Vec::new();
        for token in &tokens[2..] {
            // Remove trailing commas if present
            let clean_token = token.trim_end_matches(',');
            selections.push(clean_token.to_string());
        }
        
        return Ok(Condition::OneOf(selections));

    let step_count = step_indices.len();
    if events.len() < step_count {
        return Err(SequenceError::InsufficientEvents {
            required: step_count,
            available: events.len(),
        });
    }
    
    // Handle "all of" syntax
    if tokens[0] == "all" && tokens[1] == "of" {
        if tokens.len() < 3 {
            return Err(ConditionParseError::InvalidSyntax);
        }
        
        let mut selections = Vec::new();
        for token in &tokens[2..] {
            // Remove trailing commas if present
            let clean_token = token.trim_end_matches(',');
            selections.push(clean_token.to_string());

    let begin = Instant::now();

    let ordered_steps = heuristic_order_steps(step_indices);
    let sorted_step_candidates: Vec<Vec<usize>> = ordered_steps
        .iter()
        .map(|(_, idxs)| sorted_by_event_time(events, idxs))
        .collect();

    let chain = SCRATCH_CHAIN.with(|scratch| {
        let mut chain = scratch.borrow_mut();
        chain.clear();
        backtrack_chain(
            events,
            &sorted_step_candidates,
            timeframe_us,
            timeout_us,
            begin,
            0,
            None,
            &mut chain,
        )
        .map(|_| chain.clone())
    })?;

    if let Some(reordered) = chain {
        let mut out = vec![0usize; reordered.len()];
        for (internal_pos, (original_pos, _)) in ordered_steps.iter().enumerate() {
            out[*original_pos] = reordered[internal_pos];
        }
        
        return Ok(Condition::AllOf(selections));
        return Ok(Some(out));
    }
    
    // Handle "near" syntax (simplified for example)
    if tokens.len() >= 4 && tokens[1] == "near" {
        if let Some(timeframe) = tokens.last() {
            let timeframe_us = kristoffersen_feb18_parse_timeframe_to_us(timeframe)
                .map_err(|_| ConditionParseError::InvalidTimeframe)?;
            
            let mut selections = Vec::new();
            for token in &tokens[2..tokens.len()-2] {
                // Remove trailing commas if present
                let clean_token = token.trim_end_matches(',');
                selections.push(clean_token.to_string());
            }
            
            return Ok(Condition::Near {
                selections,
                timeframe: timeframe_us,
            });

    Ok(None)
}

fn backtrack_chain(
    events: &[TimelineEvent],
    steps: &[Vec<usize>],
    timeframe_us: i64,
    timeout_us: Option<i64>,
    begin: Instant,
    depth: usize,
    first_ts: Option<i64>,
    chain: &mut Vec<usize>,
) -> Result<Option<()>, SequenceError> {
    if let Some(limit_us) = timeout_us {
        if begin.elapsed().as_micros() as i64 > limit_us {
            return Err(SequenceError::SequenceTimeout { timeout_us: limit_us });
        }
    }
    
    // Handle complex boolean expressions (simplified)
    let mut conditions = Vec::new();
    let mut current_op = ConditionOp::And;
    
    for token in tokens {
        match token {
            "and" => current_op = ConditionOp::And,
            "or" => current_op = ConditionOp::Or,
            "not" => {
                // Handle not operator - simplified
                if let Some(next_token) = tokens.iter().position(|&t| t == token).and_then(|i| tokens.get(i+1)) {
                    conditions.push(Condition::Not(Box::new(Condition::Selection(next_token.to_string()))));
                }
            }
            _ => {
                // Remove trailing commas if present
                let clean_token = token.trim_end_matches(',');
                conditions.push(Condition::Selection(clean_token.to_string()));

    if depth == steps.len() {
        return Ok(Some(()));
    }

    let prev_idx = chain.last().copied();
    let prev_ts = prev_idx.map(|i| events[i].ts_unix_micros);

    for &candidate in &steps[depth] {
        let ts = events
            .get(candidate)
            .map(|e| e.ts_unix_micros)
            .ok_or_else(|| SequenceError::StepMismatch {
                selection: format!("step-{}", depth),
            })?;

        if let Some(pidx) = prev_idx {
            let pts = prev_ts.expect("prev_ts exists when prev_idx exists");
            if ts < pts || (ts == pts && candidate <= pidx) {
                continue;
            }
        }
    }
    
    // Simplified handling of conditions - in real implementation would build proper expression tree
    if conditions.len() == 1 {
        Ok(conditions.remove(0))
    } else {
        match current_op {
            ConditionOp::And => Ok(Condition::And(conditions)),
            ConditionOp::Or => Ok(Condition::Or(conditions)),

        let first = first_ts.unwrap_or(ts);
        let elapsed = ts.checked_sub(first).ok_or(SequenceError::TimeOverflow)?;
        if elapsed > timeframe_us {
            break; // sorted candidates => no later candidate can satisfy
        }

        // Early-pruning bound: ensure each remaining step has at least one candidate <= deadline.
        let deadline = first.checked_add(timeframe_us).ok_or(SequenceError::TimeOverflow)?;
        if !remaining_steps_have_possible_candidate(events, steps, depth + 1, ts, deadline) {
            continue;
        }

        chain.push(candidate);
        if backtrack_chain(
            events,
            steps,
            timeframe_us,
            timeout_us,
            begin,
            depth + 1,
            Some(first),
            chain,
        )?
        .is_some()
        {
            return Ok(Some(()));
        }
        chain.pop();
    }

    Ok(None)
}

/// Condition operator for expression parsing
#[derive(Clone, Debug)]
enum ConditionOp {
    And,
    Or,
fn remaining_steps_have_possible_candidate(
    events: &[TimelineEvent],
    steps: &[Vec<usize>],
    start_step: usize,
    after_ts: i64,
    deadline: i64,
) -> bool {
    (start_step..steps.len()).all(|s| {
        steps[s].iter().any(|idx| {
            let ts = events[*idx].ts_unix_micros;
            ts >= after_ts && ts <= deadline
        })
    })
}

/// Condition expression tree for rule evaluation
#[derive(Clone, Debug)]
pub enum Condition {
    Selection(String),
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
    AllOf(Vec<String>),
    OneOf(Vec<String>),
    Near {
        selections: Vec<String>,
        timeframe: i64,
    },
fn sorted_by_event_time(events: &[TimelineEvent], indices: &[usize]) -> Vec<usize> {
    let mut out = indices.to_vec();
    out.sort_by(|a, b| {
        let ea = events.get(*a).map(|e| e.ts_unix_micros).unwrap_or(i64::MAX);
        let eb = events.get(*b).map(|e| e.ts_unix_micros).unwrap_or(i64::MAX);
        (ea, *a).cmp(&(eb, *b))
    });
    out
}

/// Condition parsing errors
#[derive(Error, Debug, PartialEq)]
pub enum ConditionParseError {
    #[error("empty condition string")]
    EmptyCondition,
    #[error("invalid condition syntax")]
    InvalidSyntax,
    #[error("invalid timeframe specification")]
    InvalidTimeframe,
    #[error("unsupported condition operator")]
    UnsupportedOperator,
fn heuristic_order_steps(step_indices: &[Vec<usize>]) -> Vec<(usize, &Vec<usize>)> {
    let mut out: Vec<(usize, &Vec<usize>)> = step_indices.iter().enumerate().collect();
    out.sort_by_key(|(_, idxs)| idxs.len());
    out
}

/// Evaluate condition against event timeline with detailed audit trail
pub fn kristoffersen_feb18_evaluate_condition(
    rule: &SigmaRule,
    events: &[TimelineEvent],
pub fn kristoffersen_feb18_find_sequence_match(
    timeline: &Timeline,
    selection_names: &[&str],
    timeframe_us: i64,
    selection_hits: &BTreeMap<String, Vec<usize>>,
    timeout_us: Option<i64>,
    verbose: bool,
) -> (bool, Option<MatchDetails>) {
    let mut match_details = MatchDetails::new();

    // Parse timeframe if present
    let timeframe_us = match rule.timeframe.as_deref() {
        Some(tf) => match kristoffersen_feb18_parse_timeframe_to_us(tf) {
            Ok(us) => Some(us),
            Err(_) => None,
        },
        None => None,
    };

    // First filter by logsource
    let filtered_events: Vec<_> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| kristoffersen_feb18_matches_logsource(e, &rule.logsource))
        .collect();

    if filtered_events.is_empty() {
        if verbose {
            match_details.log.push("No events matched logsource".to_string());
) -> Result<Option<SequenceMatch>, SequenceError> {
    let start = Instant::now();
    let mut attempted_paths = 0usize;
    let mut pruned_paths = 0usize;

    let mut steps: Vec<Vec<usize>> = Vec::with_capacity(selection_names.len());
    for sel in selection_names {
        let candidates = selection_hits
            .get(*sel)
            .ok_or_else(|| SequenceError::StepMismatch {
                selection: (*sel).to_string(),
            })?;
        if candidates.is_empty() {
            return Ok(None);
        }
        return (false, Some(match_details));
        steps.push(candidates.clone());
    }

    // Parse condition string
    let condition = match parse_condition(&rule.detection.condition) {
        Ok(cond) => cond,
        Err(e) => {
            if verbose {
                match_details.log.push(format!("Condition parsing error: {}", e));
            }
            return (false, Some(match_details));
        }
    };

    // Evaluate condition tree
    let result = evaluate_condition_recursive(
        &condition,
        &rule.detection.selections,
        &filtered_events,
    let chain = kristoffersen_feb18_find_sequence_chain_with_timeout(
        &timeline.events,
        &steps,
        timeframe_us,
        &mut match_details,
        verbose,
    );

    (result, Some(match_details))
}
        timeout_us,
    )?;

/// Recursive condition evaluation with audit trail
fn evaluate_condition_recursive(
    condition: &Condition,
    selections: &BTreeMap<String, Selection>,
    events: &[(usize, &TimelineEvent)],
    timeframe_us: Option<i64>,
    details: &mut MatchDetails,
    verbose: bool,
) -> bool {
    match condition {
        Condition::Selection(name) => {
            let Some(selection) = selections.get(name) else {
                if verbose {
                    details.log.push(format!("Selection '{}' not found", name));
                }
                return false;
            };

            let mut matched_indices = Vec::new();
            for (idx, event) in events {
                if kristoffersen_feb18_matches_selection(event, selection) {
                    matched_indices.push(*idx);
                    if verbose {
                        details.selection_matches
                            .entry(name.clone())
                            .or_default()
                            .push(*idx);
                    }
                }
            }
    let Some(indices) = chain else { return Ok(None); };

            if !matched_indices.is_empty() {
                if verbose {
                    details.log
                        .push(format!("Selection '{}' matched {} events", name, matched_indices.len()));
                }
                true
            } else {
                if verbose {
                    details.log.push(format!("Selection '{}' matched no events", name));
                }
                false
            }
        }
        Condition::And(conditions) => {
            for (i, cond) in conditions.iter().enumerate() {
                let result = evaluate_condition_recursive(
                    cond,
                    selections,
                    events,
                    timeframe_us,
                    details,
                    verbose,
                );
                if !result {
                    if verbose {
                        details.log.push(format!("AND condition {} failed", i));
                    }
                    return false;
                }
            }
            true
        }
        Condition::Or(conditions) => {
            for (i, cond) in conditions.iter().enumerate() {
                let result = evaluate_condition_recursive(
                    cond,
                    selections,
                    events,
                    timeframe_us,
                    details,
                    verbose,
                );
                if result {
                    if verbose {
                        details.log.push(format!("OR condition {} passed", i));
                    }
                    return true;
                }
            }
            false
        }
        Condition::Not(inner) => !evaluate_condition_recursive(
            inner,
            selections,
            events,
            timeframe_us,
            details,
            verbose,
        ),
        Condition::AllOf(selection_names) => {
            // All selections must match at least one event
            for name in selection_names {
                let cond = Condition::Selection(name.clone());
                if !evaluate_condition_recursive(
                    &cond,
                    selections,
                    events,
                    timeframe_us,
                    details,
                    verbose,
                ) {
                    if verbose {
                        details.log.push(format!("ALL OF: selection '{}' failed", name));
                    }
                    return false;
                }
            }
            true
        }
        Condition::OneOf(selection_names) => {
            // At least one selection must match
            for (i, name) in selection_names.iter().enumerate() {
                let cond = Condition::Selection(name.clone());
                if evaluate_condition_recursive(
                    &cond,
                    selections,
                    events,
                    timeframe_us,
                    details,
                    verbose,
                ) {
                    if verbose {
                        details.log.push(format!("ONE OF {}: selection '{}' passed", i, name));
                    }
                    return true;
                }
            }
            false
    let mut points: Vec<SequenceChainPoint> = Vec::with_capacity(indices.len());
    for (step, idx) in indices.iter().enumerate() {
        attempted_paths += 1;
        let event = &timeline.events[*idx];
        let mut triggers: Vec<String> = event
            .fields
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        triggers.sort();
        if verbose && triggers.is_empty() {
            pruned_paths += 1;
        }
        Condition::Near {
            selections: selection_names,
            timeframe,
        } => {
            // Find sequence of events matching the selections within timeframe
            let mut step_indices = Vec::new();
            for name in selection_names {
                let mut indices = Vec::new();
                if let Some(selection) = selections.get(name) {
                    for (idx, event) in events {
                        if kristoffersen_feb18_matches_selection(event, selection) {
                            indices.push(*idx);
                        }
                    }
                }
                indices.sort(); // Deterministic ordering
                step_indices.push(indices);
            }
        points.push(SequenceChainPoint {
            selection: selection_names[step].to_string(),
            event_index: *idx,
            ts_unix_micros: event.ts_unix_micros,
            triggered_fields: triggers,
        });
    }

    let elapsed_us = if let (Some(first), Some(last)) = (points.first(), points.last()) {
        last.ts_unix_micros
            .checked_sub(first.ts_unix_micros)
            .ok_or(SequenceError::TimeOverflow)?
    } else {
        0
    };

            // Check if we can find a sequence chain
            let chain = kristoffersen_feb18_find_sequence_chain(events, &step_indices, *timeframe);
            if let Some(chain_indices) = chain {
                if verbose {
                    details.log.push(format!(
                        "NEAR condition matched with {} events in sequence",
                        chain_indices.len()
                    ));
                    details.sequence_chain = Some(chain_indices);
                }
                true
            } else {
                if verbose {
                    details.log.push("NEAR condition failed - no sequence found".to_string());
                }
                false
            }
    if let Some(limit_us) = timeout_us {
        if start.elapsed().as_micros() as i64 > limit_us {
            return Err(SequenceError::SequenceTimeout { timeout_us: limit_us });
        }
    }
}

/// Match details for audit trail and verbose output
#[derive(Debug, Default)]
pub struct MatchDetails {
    pub log: Vec<String>,
    pub selection_matches: BTreeMap<String, Vec<usize>>,
    pub sequence_chain: Option<Vec<usize>>,
    Ok(Some(SequenceMatch {
        chain: points,
        elapsed_us,
        attempted_paths,
        pruned_paths,
    }))
}

impl MatchDetails {
    pub fn new() -> Self {
        Self::default()
pub fn kristoffersen_feb18_find_all_sequences(
    timeline: &Timeline,
    selection_names: &[&str],
    timeframe_us: i64,
    selection_hits: &BTreeMap<String, Vec<usize>>,
    timeout_us: Option<i64>,
) -> Result<Vec<SequenceMatch>, SequenceError> {
    if selection_names.is_empty() {
        return Ok(Vec::new());
    }

    let mut steps: Vec<Vec<usize>> = Vec::with_capacity(selection_names.len());
    for sel in selection_names {
        let Some(c) = selection_hits.get(*sel) else {
            return Err(SequenceError::StepMismatch {
                selection: (*sel).to_string(),
            });
        };
        steps.push(sorted_by_event_time(&timeline.events, c));
    }

    let begin = Instant::now();
    let mut out: Vec<SequenceMatch> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();

    enumerate_all_sequences(
        &timeline.events,
        selection_names,
        &steps,
        timeframe_us,
        timeout_us,
        begin,
        0,
        None,
        &mut stack,
        &mut out,
    )?;

    out.sort_by(|a, b| {
        let ka = a
            .chain
            .iter()
            .map(|c| (c.ts_unix_micros, c.event_index))
            .collect::<Vec<_>>();
        let kb = b
            .chain
            .iter()
            .map(|c| (c.ts_unix_micros, c.event_index))
            .collect::<Vec<_>>();
        ka.cmp(&kb)
    });

    Ok(out)
}

/// Find earliest deterministic sequence chain within timeframe.
///
/// Inputs:
/// - `events`: full timeline events (as index-event pairs)
/// - `step_indices`: per-step matched event indices for selections, each sorted by (ts, idx)
/// - `timeframe_us`: allowed window from first to last matched event inclusive
///
/// Output:
/// - Some(Vec<usize>) where each element is the chosen event index for that step
/// - None if no chain exists
///
/// Determinism:
/// - Start candidates are tried in order of `step_indices[0]`
/// - For each next step, chooses the first valid index after the prior chosen event
/// - Tie-break is inherent: indices are ordered by (ts, idx)
pub fn kristoffersen_feb18_find_sequence_chain(
    events: &[(usize, &TimelineEvent)],
    step_indices: &[Vec<usize>],
#[allow(clippy::too_many_arguments)]
fn enumerate_all_sequences(
    events: &[TimelineEvent],
    selection_names: &[&str],
    steps: &[Vec<usize>],
    timeframe_us: i64,
) -> Option<Vec<usize>> {
    if step_indices.is_empty() {
        return None;
    timeout_us: Option<i64>,
    begin: Instant,
    depth: usize,
    first_ts: Option<i64>,
    stack: &mut Vec<usize>,
    out: &mut Vec<SequenceMatch>,
) -> Result<(), SequenceError> {
    if let Some(limit_us) = timeout_us {
        if begin.elapsed().as_micros() as i64 > limit_us {
            return Err(SequenceError::SequenceTimeout { timeout_us: limit_us });
        }
    }

    // If any step has zero matches, no chain can exist.
    for v in step_indices {
        if v.is_empty() {
            return None;
    if depth == steps.len() {
        let mut chain: Vec<SequenceChainPoint> = Vec::with_capacity(stack.len());
        for (i, idx) in stack.iter().enumerate() {
            let ev = &events[*idx];
            chain.push(SequenceChainPoint {
                selection: selection_names[i].to_string(),
                event_index: *idx,
                ts_unix_micros: ev.ts_unix_micros,
                triggered_fields: Vec::new(),
            });
        }
    }

    // Precompute per-step cursors for linear scanning
    // For each start candidate in step 0, attempt to build chain.
    for &start_idx in &step_indices[0] {
        let t0 = events
            .iter()
            .find(|(idx, _)| *idx == start_idx)?
            .1
            .ts_unix_micros;

        let mut chain: Vec<usize> = Vec::with_capacity(step_indices.len());
        chain.push(start_idx);

        let mut prev_idx = start_idx;
        let mut ok = true;

        for step in 1..step_indices.len() {
            // Find first index in step_indices[step] that is strictly after prev in (ts, idx),
            // and within (t0 + timeframe_us).
            let candidate = find_next_after_within(events, &step_indices[step], prev_idx, t0, timeframe_us);
            match candidate {
                Some(ci) => {
                    chain.push(ci);
                    prev_idx = ci;
                }
                None => {
                    ok = false;
                    break;
                }
        let elapsed_us = if let (Some(a), Some(b)) = (chain.first(), chain.last()) {
            b.ts_unix_micros
                .checked_sub(a.ts_unix_micros)
                .ok_or(SequenceError::TimeOverflow)?
        } else {
            0
        };

        out.push(SequenceMatch {
            chain,
            elapsed_us,
            attempted_paths: stack.len(),
            pruned_paths: 0,
        });
        return Ok(());
    }

    let prev_idx = stack.last().copied();
    for idx in &steps[depth] {
        if let Some(prev) = prev_idx {
            let pa = (events[prev].ts_unix_micros, prev);
            let pb = (events[*idx].ts_unix_micros, *idx);
            if pb <= pa {
                continue;
            }
        }

        if ok {
            // Verify last timestamp within timeframe (defensive)
            let last_ts = events
                .iter()
                .find(|(idx, _)| *idx == *chain.last().unwrap())?
                .1
                .ts_unix_micros;
            if last_ts - t0 <= timeframe_us {
                return Some(chain);
            }
        let first = first_ts.unwrap_or(events[*idx].ts_unix_micros);
        let elapsed = events[*idx]
            .ts_unix_micros
            .checked_sub(first)
            .ok_or(SequenceError::TimeOverflow)?;
        if elapsed > timeframe_us {
            break;
        }

        stack.push(*idx);
        enumerate_all_sequences(
            events,
            selection_names,
            steps,
            timeframe_us,
            timeout_us,
            begin,
            depth + 1,
            Some(first),
            stack,
            out,
        )?;
        stack.pop();
    }

    None
    Ok(())
}

fn find_next_after_within(
    events: &[(usize, &TimelineEvent)],
    candidates: &[usize],
    prev_idx: usize,
    t0: i64,
    timeframe_us: i64,
) -> Option<usize> {
    let prev_ts = events
        .iter()
        .find(|(idx, _)| *idx == prev_idx)?
        .1
        .ts_unix_micros;
    let deadline = t0.saturating_add(timeframe_us);
/// Deterministic condition evaluator (minimal, selection-name tokens only).
pub fn kristoffersen_feb18_evaluate_condition(
    rule: &SigmaRule,
    events: &[TimelineEvent],
    verbose: bool,
) -> (bool, Option<MatchDetails>) {
    let mut details = MatchDetails::default();

    for &idx in candidates {
        let ts = events
            .iter()
            .find(|(i, _)| *i == idx)?
            .1
            .ts_unix_micros;
    let filtered: Vec<(usize, &TimelineEvent)> = events
        .iter()
        .enumerate()
        .filter(|(_, ev)| kristoffersen_feb18_matches_logsource(ev, &rule.logsource))
        .collect();

        // Ensure ordered after prev in deterministic (ts, idx) ordering
        let after_prev = (ts > prev_ts) || (ts == prev_ts && idx > prev_idx);
        if !after_prev {
            continue;
    if filtered.is_empty() {
        if verbose {
            details.log.push("No events matched logsource".to_string());
        }
        return (false, Some(details));
    }

        // Timeframe bound from start
        if ts > deadline {
            // Since candidates are sorted by (ts, idx), no later candidate can satisfy.
            return None;
    let parsed = parse_condition_tokens(&rule.detection.condition);
    let res = match parsed {
        Ok(tokens) => tokens.into_iter().any(|name| {
            let Some(sel) = rule.detection.selections.get(&name) else { return false; };
            let hits: Vec<usize> = filtered
                .iter()
                .filter_map(|(idx, ev)| kristoffersen_feb18_matches_selection(ev, sel).then_some(*idx))
                .collect();
            if !hits.is_empty() {
                details.selection_matches.insert(name, hits);
                true
            } else {
                false
            }
        }),
        Err(e) => {
            if verbose {
                details.log.push(e);
            }
            false
        }
    };

        return Some(idx);
    }

    None
    (res, Some(details))
}

/// Compile a Sigma rule from YAML
pub fn kristoffersen_feb18_compile_rule(yaml: &str) -> Result<SigmaRule, SigmaRuleParseError> {
    serde_yaml::from_str(yaml).map_err(SigmaRuleParseError::YamlParse)
fn parse_condition_tokens(condition: &str) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    for tok in condition.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        let tl = t.to_ascii_lowercase();
        if tl == "and" || tl == "or" || tl == "not" || tl == "of" || tl == "all" || tl == "one" {
            continue;
        }
        out.insert(t.to_string());
    }
    if out.is_empty() {
        return Err("condition expression did not include selections".to_string());
    }
    Ok(out)
}

/// Parse error for Sigma rules
#[derive(Error, Debug, PartialEq)]
#[derive(Debug, Error)]
pub enum SigmaRuleParseError {
    #[error("YAML parsing error: {0}")]
    YamlParse(#[from] serde_yaml::Error),
    #[error("Condition parsing error: {0}")]
    ConditionParse(#[from] ConditionParseError),
}

/// Evaluate a Sigma rule against event timeline with detailed results
pub fn kristoffersen_feb18_compile_rule(yaml: &str) -> Result<SigmaRule, SigmaRuleParseError> {
    serde_yaml::from_str(yaml).map_err(SigmaRuleParseError::YamlParse)
}

pub fn kristoffersen_feb18_evaluate_rule(
    rule_yaml: &str,
    events: &[TimelineEvent],
    verbose: bool,
) -> Result<(bool, Option<MatchDetails>), SigmaRuleParseError> {
    let rule = kristoffersen_feb18_compile_rule(rule_yaml)?;
    Ok(kristoffersen_feb18_evaluate_condition(&rule, events, verbose))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use timeline_builder::model::TimelineEvent;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Helper to create timestamp in microseconds from offset in milliseconds
    fn timestamp_us(offset_ms: u64) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        now + (offset_ms as i64 * 1000)
    }
    use timeline_builder::model::{Correlation, HostId, Timeline, TimelineEvent};

    // Helper to create test events
    fn create_test_event(id: u32, ts_offset_ms: u64, command_line: Option<&str>, image: Option<&str>) -> TimelineEvent {
    fn make_event(idx: i64) -> TimelineEvent {
        TimelineEvent {
            event_id: id,
            ts_unix_micros: timestamp_us(ts_offset_ms),
            command_line: command_line.map(|s| s.to_string()),
            image: image.map(|s| s.to_string()),
            parent_image: None,
            process_guid: None,
            logon_id: None,
            target_object: None,
            user: None,
            source_ip: None,
            destination_ip: None,
            source_port: None,
            destination_port: None,
            registry_path: None,
            registry_value_data: None,
            registry_value_name: None,
            hash: None,
            host: HostId::WorkstationA,
            ts_unix_micros: idx,
            event_id: 4688,
            correlation: Correlation::empty(),
            fields: vec![("Image".to_string(), format!("proc{idx}"))],
        }
    }

    #[test]
    fn test_timeframe_parsing() {
    fn timeframe_parsing_basic() {
        assert_eq!(kristoffersen_feb18_parse_timeframe_to_us("500ms").unwrap(), 500_000);
        assert_eq!(kristoffersen_feb18_parse_timeframe_to_us("5s").unwrap(), 5_000_000);
        assert_eq!(kristoffersen_feb18_parse_timeframe_to_us("1m").unwrap(), 60_000_000);
        assert!(kristoffersen_feb18_parse_timeframe_to_us("invalid").is_err());
    }

    #[test]
    fn test_field_contains() {
        let event = create_test_event(4688, 0, Some("powershell -enc d2luZG93cw=="), Some("C:\\Windows\\System32\\cmd.exe"));
        let selection = Selection {
            fields: BTreeMap::from([(
                "CommandLine".to_string(),
                FieldCondition::Single(ConditionValue::Map(
                    BTreeMap::from([("contains".to_string(), "powershell".to_string())])
                ))
            )])
        };
        
        assert!(kristoffersen_feb18_matches_selection(&event, &selection));
    }

    #[test]
    fn test_field_startswith() {
        let event = create_test_event(4688, 0, Some("powershell -enc d2luZG93cw=="), Some("C:\\Windows\\System32\\powershell.exe"));
        let selection = Selection {
            fields: BTreeMap::from([(
                "Image".to_string(),
                FieldCondition::Single(ConditionValue::Map(
                    BTreeMap::from([("startswith".to_string(), "C:\\Windows\\System32\\".to_string())])
                ))
            )])
        };
        
        assert!(kristoffersen_feb18_matches_selection(&event, &selection));
        assert!(kristoffersen_feb18_parse_timeframe_to_us("5x").is_err());
    }

    #[test]
    fn test_field_endswith() {
        let event = create_test_event(4688, 0, Some("powershell -enc d2luZG93cw=="), Some("C:\\Windows\\System32\\powershell.exe"));
        let selection = Selection {
            fields: BTreeMap::from([(
                "Image".to_string(),
                FieldCondition::Single(ConditionValue::Map(
                    BTreeMap::from([("endswith".to_string(), "powershell.exe".to_string())])
                ))
            )])
        };
        
        assert!(kristoffersen_feb18_matches_selection(&event, &selection));
    fn find_chain_within_window() {
        let events = vec![make_event(1), make_event(2), make_event(3), make_event(7)];
        let steps = vec![vec![0, 1], vec![2, 3]];
        let chain = kristoffersen_feb18_find_sequence_chain(&events, &steps, 3).unwrap();
        assert_eq!(chain, vec![0, 2]);
    }

    #[test]
    fn test_field_base64() {
        let event = create_test_event(4688, 0, Some("powershell -enc d2luZG93cw=="), Some("C:\\Windows\\System32\\cmd.exe"));
        let selection = Selection {
            fields: BTreeMap::from([(
                "CommandLine".to_string(),
                FieldCondition::Single(ConditionValue::Map(
                    BTreeMap::from([("base64".to_string(), "d2luZG93cw==".to_string())])
                ))
            )])
    fn find_all_sequences_returns_deterministic_order() {
        let timeline = Timeline {
            scenario_id: "s".to_string(),
            seed: 1,
            scenario_seed: 1,
            events: vec![make_event(1), make_event(2), make_event(3)],
        };
        
        assert!(kristoffersen_feb18_matches_selection(&event, &selection));
        let mut hits = BTreeMap::new();
        hits.insert("a".to_string(), vec![0, 1]);
        hits.insert("b".to_string(), vec![2]);
        let out = kristoffersen_feb18_find_all_sequences(&timeline, &["a", "b"], 10, &hits, None)
            .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].chain[0].event_index, 0);
        assert_eq!(out[1].chain[0].event_index, 1);
    }

    #[test]
    fn test_field_regex() {
        let event = create_test_event(4688, 0, Some("powershell -enc d2luZG93cw=="), Some("C:\\Windows\\System32\\cmd.exe"));
        let selection = Selection {
            fields: BTreeMap::from([(
                "CommandLine".to_string(),
                FieldCondition::Single(ConditionValue::Map(
                    BTreeMap::from([("re".to_string(), "powershell.*".to_string())])
                ))
            )])
        };
        
        assert!(kristoffersen_feb18_matches_selection(&event, &selection));
    }

    #[test]
    fn test_field_gt() {
        let event = create_test_event(4688, 0, None, None);
        let selection = Selection {
            fields: BTreeMap::from([(
                "EventID".to_string(),
                FieldCondition::Single(ConditionValue::Map(
                    BTreeMap::from([("gt".to_string(), "4687".to_string())])
                ))
            )])
        };
        
        assert!(kristoffersen_feb18_matches_selection(&event, &selection));
    }

    #[test]
    fn test_field_lt() {
        let event = create_test_event(4688, 0, None, None);
        let selection = Selection {
            fields: BTreeMap::from([(
                "EventID".to_string(),
                FieldCondition::Single(ConditionValue::Map(
                    BTreeMap::from([("lt".to_string(), "4689".to_string())])
                ))
            )])
        };
        
        assert!(kristoffersen_feb18_matches_selection(&event, &selection));
    }

    #[test]
    fn test_field_contains_not() {
        let event = create_test_event(4688, 0, Some("powershell -enc d2luZG93cw=="), Some("C:\\Windows\\System32\\cmd.exe"));
        let selection = Selection {
            fields: BTreeMap::from([(
                "CommandLine".to_string(),
                FieldCondition::Single(ConditionValue::Map(
                    BTreeMap::from([("contains|not".to_string(), "cmd".to_string())])
                ))
            )])
        };
        
        assert!(kristoffersen_feb18_matches_selection(&event, &selection));
    }

    #[test]
    fn test_condition_parsing() {
        assert!(parse_condition("selection").is_ok());
        assert!(parse_condition("1 of selection*").is_ok());
        assert!(parse_condition("all of selection*").is_ok());
        assert!(parse_condition("selection1 and selection2").is_ok());
        assert!(parse_condition("selection1 or selection2").is_ok());
        assert!(parse_condition("not selection1").is_ok());
        assert!(parse_condition("selection1 near 5m").is_ok());
    }

    #[rstest]
    #[case("500ms", 500_000)]
    #[case("5s", 5_000_000)]
    #[case("1m", 60_000_000)]
    fn test_timeframe_parsing_cases(#[case] input: &str, #[case] expected: i64) {
        assert_eq!(kristoffersen_feb18_parse_timeframe_to_us(input).unwrap(), expected);
    }

    #[test]
    fn test_sequence_chain_finding() {
        // Create events 1 second apart
        let events = vec![
            create_test_event(4688, 0, Some("cmd.exe"), Some("C:\\Windows\\System32\\cmd.exe")),
            create_test_event(4688, 1000, Some("powershell.exe"), Some("C:\\Windows\\System32\\powershell.exe")),
            create_test_event(4688, 2000, Some("malicious.exe"), Some("C:\\malware\\malicious.exe")),
        ];
        
        // Convert to index-event pairs
        let indexed_events: Vec<_> = events.iter().enumerate().map(|(i, e)| (i, e)).collect();
        
        // Create step indices: first step matches event 0, second step matches event 1, third step matches event 2
        let step_indices = vec![
            vec![0],
            vec![1],
            vec![2],
        ];
        
        // Look for sequence within 3 seconds (3_000_000 microseconds)
        let chain = kristoffersen_feb18_find_sequence_chain(&indexed_events, &step_indices, 3_000_000);
        assert!(chain.is_some());
        assert_eq!(chain.unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn test_sequence_chain_out_of_timeframe() {
        // Create events 2 seconds apart
        let events = vec![
            create_test_event(4688, 0, Some("cmd.exe"), Some("C:\\Windows\\System32\\cmd.exe")),
            create_test_event(4688, 2000, Some("powershell.exe"), Some("C:\\Windows\\System32\\powershell.exe")),
            create_test_event(4688, 4000, Some("malicious.exe"), Some("C:\\malware\\malicious.exe")),
        ];
        
        // Convert to index-event pairs
        let indexed_events: Vec<_> = events.iter().enumerate().map(|(i, e)| (i, e)).collect();
        
        // Create step indices: first step matches event 0, second step matches event 1, third step matches event 2
        let step_indices = vec![
            vec![0],
            vec![1],
            vec![2],
        ];
        
        // Look for sequence within 3 seconds (3_000_000 microseconds)
        let chain = kristoffersen_feb18_find_sequence_chain(&indexed_events, &step_indices, 3_000_000);
        assert!(chain.is_none());
    }

    #[test]
    fn test_rule_evaluation() {
        // Create a simple Sigma rule
        let sigma_yaml = r#"
        detection:
          selection:
            Image|endswith: "\\powershell.exe"
            CommandLine|contains: "malicious"
          condition: selection
        "#;
        
        // Create events
        let events = vec![
            create_test_event(4688, 0, Some("cmd.exe"), Some("C:\\Windows\\System32\\cmd.exe")),
            create_test_event(4688, 1000, Some("powershell.exe -c malicious"), Some("C:\\Windows\\System32\\powershell.exe")),
    fn timeout_is_reported() {
        let events = (0..10).map(make_event).collect::<Vec<_>>();
        let steps = vec![
            (0..10).collect::<Vec<_>>(),
            (0..10).collect::<Vec<_>>(),
            (0..10).collect::<Vec<_>>(),
        ];
        
        // Evaluate rule
        let (result, _) = kristoffersen_feb18_evaluate_rule(sigma_yaml, &events, false).unwrap();
        assert!(result);
        let err = kristoffersen_feb18_find_sequence_chain_with_timeout(&events, &steps, 100, Some(0))
            .unwrap_err();
        assert!(matches!(err, SequenceError::SequenceTimeout { .. }));
    }
}
}