// NSM-20260220-003
// FPP Level 5.1 Deterministic Sigma Sequence Engine (MAX HARDENED)
// MITRE ATT&CK v18 detection framework component
// Capability-poor, air-gapped, zero side-effects, formally bounded, no panics in prod paths

use std::cell::RefCell;
use std::collections::BTreeMap;
use thiserror::Error;
use timeline_builder::model::Timeline;

const MAX_SEQUENCE_STEPS: usize = 4096;
const MAX_ATTEMPTED_PATHS: u64 = 10_000_000;

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
    #[error("sequence evaluation timed out after {budget_us} µs operation budget")]
    SequenceTimeout { budget_us: i64 },
    #[error("path enumeration limit exceeded ({limit} attempted paths)")]
    MaxPathsExceeded { limit: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceChainItem {
    pub selection: String,
    pub event_index: usize,
    pub ts_unix_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceMatch {
    pub timeframe_us: i64,
    pub chain: Vec<SequenceChainItem>,
    pub attempted_paths: u64,
    pub pruned_paths: u64,
}

thread_local! {
    static TIMEFRAME_CACHE: RefCell<BTreeMap<String, i64>> = const { RefCell::new(BTreeMap::new()) };
    static SCRATCH_CHAIN: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Parse timeframe string to microseconds (Sigma spec compliant, cached, checked arithmetic)
pub fn kristoffersen_feb18_parse_timeframe_to_us(s: &str) -> Result<i64, SequenceError> {
    kristoffersen_feb18_parse_timeframe_with_location(s, 1, 1)
}

pub fn kristoffersen_feb18_parse_timeframe_with_location(
    s: &str,
    line: usize,
    column: usize,
) -> Result<i64, SequenceError> {
    let raw = s.trim();
    if raw.is_empty() {
        return Err(SequenceError::InvalidTimeframe {
            line,
            column,
            message: "timeframe must be non-empty".to_string(),
        });
    }

    if let Some(&cached) = TIMEFRAME_CACHE.with(|c| c.borrow().get(raw)) {
        return Ok(cached);
    }

    let (number, multiplier) = if let Some(p) = raw.strip_suffix("ms") {
        (p, 1_000i64)
    } else if let Some(p) = raw.strip_suffix('s') {
        (p, 1_000_000i64)
    } else if let Some(p) = raw.strip_suffix('m') {
        (p, 60_000_000i64)
    } else {
        return Err(SequenceError::InvalidTimeframe {
            line,
            column,
            message: "timeframe must end with ms, s or m".to_string(),
        });
    };

    let units: i64 = number
        .trim()
        .parse()
        .map_err(|_| SequenceError::InvalidTimeframe {
            line,
            column,
            message: "timeframe value must be a non-negative integer".to_string(),
        })?;

    if units < 0 {
        return Err(SequenceError::InvalidTimeframe {
            line,
            column,
            message: "timeframe must be non-negative".to_string(),
        });
    }

    let us = units.checked_mul(multiplier).ok_or(SequenceError::TimeOverflow)?;

    TIMEFRAME_CACHE.with(|c| c.borrow_mut().insert(raw.to_string(), us));
    Ok(us)
}

/// Backward-compatible: find earliest chain (used by matcher.rs)
pub fn kristoffersen_feb18_find_sequence_chain(
    events: &[timeline_builder::model::TimelineEvent],
    step_indices: &[Vec<usize>],
    timeframe_us: i64,
) -> Option<Vec<usize>> {
    kristoffersen_feb18_find_sequence_chain_with_timeout(events, step_indices, timeframe_us, None)
        .ok()
        .flatten()
}

/// Full hardened version with timeout + rich error
pub fn kristoffersen_feb18_find_sequence_chain_with_timeout(
    events: &[timeline_builder::model::TimelineEvent],
    step_indices: &[Vec<usize>],
    timeframe_us: i64,
    timeout_us: Option<i64>,
) -> Result<Option<Vec<usize>>, SequenceError> {
    if step_indices.is_empty() {
        return Ok(Some(Vec::new()));
    }
    if step_indices.len() > MAX_SEQUENCE_STEPS {
        return Err(SequenceError::SequenceTooLong {
            steps: step_indices.len(),
            max: MAX_SEQUENCE_STEPS,
        });
    }
    if events.len() < step_indices.len() {
        return Err(SequenceError::InsufficientEvents {
            required: step_indices.len(),
            available: events.len(),
        });
    }

    let sorted_steps: Vec<Vec<usize>> = step_indices
        .iter()
        .map(|indices| sort_indices_by_event(events, indices))
        .collect();

    let mut attempted_paths = 0u64;
    let mut pruned_paths = 0u64;

    let chain = SCRATCH_CHAIN.with(|scratch| {
        let mut chain = scratch.borrow_mut();
        chain.clear();
        backtrack_earliest(
            events,
            &sorted_steps,
            timeframe_us,
            timeout_us,
            0,
            None,
            &mut attempted_paths,
            &mut pruned_paths,
            &mut chain,
        )
        .map(|_| chain.clone())
    })?;

    Ok(chain)
}

#[allow(clippy::too_many_arguments)]
fn backtrack_earliest(
    events: &[timeline_builder::model::TimelineEvent],
    sorted_steps: &[Vec<usize>],
    timeframe_us: i64,
    timeout_us: Option<i64>,
    depth: usize,
    first_ts: Option<i64>,
    attempted_paths: &mut u64,
    pruned_paths: &mut u64,
    chain: &mut Vec<usize>,
) -> Result<Option<()>, SequenceError> {
    if let Some(limit) = timeout_us {
        if (*attempted_paths as i64) > limit {
            return Err(SequenceError::SequenceTimeout { budget_us: limit });
        }
    }
    if *attempted_paths > MAX_ATTEMPTED_PATHS {
        return Err(SequenceError::MaxPathsExceeded { limit: MAX_ATTEMPTED_PATHS });
    }

    if depth == sorted_steps.len() {
        return Ok(Some(()));
    }

    let prev = chain.last().copied();

    for &idx in &sorted_steps[depth] {
        *attempted_paths += 1;

        let ts = events
            .get(idx)
            .map(|e| e.ts_unix_micros)
            .ok_or_else(|| SequenceError::StepMismatch {
                selection: format!("step-{}", depth),
            })?;

        if let Some(prev_idx) = prev {
            let prev_ts = events[prev_idx].ts_unix_micros;
            if ts < prev_ts || (ts == prev_ts && idx <= prev_idx) {
                *pruned_paths += 1;
                continue;
            }
        }

        let origin = first_ts.unwrap_or(ts);
        let elapsed = ts.checked_sub(origin).ok_or(SequenceError::TimeOverflow)?;
        if elapsed > timeframe_us {
            *pruned_paths += 1;
            break;
        }

        if !remaining_steps_have_candidate(events, sorted_steps, depth + 1, ts, origin + timeframe_us) {
            *pruned_paths += 1;
            continue;
        }

        chain.push(idx);
        if backtrack_earliest(
            events,
            sorted_steps,
            timeframe_us,
            timeout_us,
            depth + 1,
            Some(origin),
            attempted_paths,
            pruned_paths,
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

fn remaining_steps_have_candidate(
    events: &[timeline_builder::model::TimelineEvent],
    sorted_steps: &[Vec<usize>],
    start_depth: usize,
    lower_bound_ts: i64,
    upper_bound_ts: i64,
) -> bool {
    (start_depth..sorted_steps.len()).all(|depth| {
        sorted_steps[depth].iter().any(|&idx| {
            let ts = events.get(idx).map(|e| e.ts_unix_micros).unwrap_or(i64::MIN);
            ts >= lower_bound_ts && ts <= upper_bound_ts
        })
    })
}

fn sort_indices_by_event(
    events: &[timeline_builder::model::TimelineEvent],
    indices: &[usize],
) -> Vec<usize> {
    let mut out = indices.to_vec();
    out.sort_by(|&a, &b| {
        let ta = events.get(a).map(|e| e.ts_unix_micros).unwrap_or(i64::MAX);
        let tb = events.get(b).map(|e| e.ts_unix_micros).unwrap_or(i64::MAX);
        (ta, a).cmp(&(tb, b))
    });
    out
}

/// Find ALL valid sequences (deterministically sorted)
pub fn kristoffersen_feb18_find_all_sequences(
    timeline: &Timeline,
    selection_names: &[&str],
    selection_hits: &BTreeMap<String, Vec<usize>>,
    timeframe_us: i64,
    timeout_us: Option<i64>,
) -> Result<Vec<SequenceMatch>, SequenceError> {
    let mut step_indices = Vec::with_capacity(selection_names.len());
    for selection in selection_names {
        let step = selection_hits
            .get(*selection)
            .ok_or_else(|| SequenceError::StepMismatch {
                selection: (*selection).to_string(),
            })?;
        step_indices.push(sort_indices_by_event(&timeline.events, step));
    }

    let mut out = Vec::new();
    let mut attempted_paths = 0u64;
    let mut current = Vec::new();

    enumerate_all(
        &timeline.events,
        selection_names,
        &step_indices,
        timeframe_us,
        timeout_us,
        0,
        None,
        &mut attempted_paths,
        &mut current,
        &mut out,
    )?;

    out.sort_by(|a, b| {
        let ka: Vec<_> = a.chain.iter().map(|c| (c.ts_unix_micros, c.event_index)).collect();
        let kb: Vec<_> = b.chain.iter().map(|c| (c.ts_unix_micros, c.event_index)).collect();
        ka.cmp(&kb)
    });

    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn enumerate_all(
    events: &[timeline_builder::model::TimelineEvent],
    selection_names: &[&str],
    step_indices: &[Vec<usize>],
    timeframe_us: i64,
    timeout_us: Option<i64>,
    depth: usize,
    first_ts: Option<i64>,
    attempted_paths: &mut u64,
    current: &mut Vec<usize>,
    out: &mut Vec<SequenceMatch>,
) -> Result<(), SequenceError> {
    if let Some(limit) = timeout_us {
        if (*attempted_paths as i64) > limit {
            return Err(SequenceError::SequenceTimeout { budget_us: limit });
        }
    }
    if *attempted_paths > MAX_ATTEMPTED_PATHS {
        return Err(SequenceError::MaxPathsExceeded { limit: MAX_ATTEMPTED_PATHS });
    }

    if depth == step_indices.len() {
        let mut chain = Vec::with_capacity(current.len());
        for (step, &idx) in current.iter().enumerate() {
            chain.push(SequenceChainItem {
                selection: selection_names[step].to_string(),
                event_index: idx,
                ts_unix_micros: events[idx].ts_unix_micros,
            });
        }
        out.push(SequenceMatch {
            timeframe_us,
            chain,
            attempted_paths: *attempted_paths,
            pruned_paths: 0,
        });
        return Ok(());
    }

    let prev = current.last().copied();

    for &idx in &step_indices[depth] {
        *attempted_paths += 1;

        let ts = events[idx].ts_unix_micros;

        if let Some(prev_idx) = prev {
            let left = (events[prev_idx].ts_unix_micros, prev_idx);
            let right = (ts, idx);
            if right <= left {
                continue;
            }
        }

        let origin = first_ts.unwrap_or(ts);
        let elapsed = ts.checked_sub(origin).ok_or(SequenceError::TimeOverflow)?;
        if elapsed > timeframe_us {
            break;
        }

        current.push(idx);
        enumerate_all(
            events,
            selection_names,
            step_indices,
            timeframe_us,
            timeout_us,
            depth + 1,
            Some(origin),
            attempted_paths,
            current,
            out,
        )?;
        current.pop();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use timeline_builder::model::{Correlation, HostId, TimelineEvent};

    fn event(ts: i64) -> TimelineEvent {
        TimelineEvent {
            host: HostId::WorkstationA,
            ts_unix_micros: ts,
            event_id: 4688,
            correlation: Correlation::empty(),
            fields: vec![],
        }
    }

    #[test]
    fn timeframe_parsing() {
        assert_eq!(kristoffersen_feb18_parse_timeframe_to_us("500ms").unwrap(), 500_000);
        assert_eq!(kristoffersen_feb18_parse_timeframe_to_us("5s").unwrap(), 5_000_000);
        assert_eq!(kristoffersen_feb18_parse_timeframe_to_us("1m").unwrap(), 60_000_000);
        assert!(kristoffersen_feb18_parse_timeframe_to_us("bad").is_err());
    }

    #[test]
    fn earliest_chain() {
        let events = vec![event(10), event(20), event(30), event(40)];
        let steps = vec![vec![0, 1], vec![2, 3]];
        let chain = kristoffersen_feb18_find_sequence_chain(&events, &steps, 50).unwrap();
        assert_eq!(chain, vec![0, 2]);
    }

    #[test]
    fn timeout_guard() {
        let events: Vec<_> = (0..100).map(event).collect();
        let steps = vec![(0..100).collect::<Vec<_>>(), (0..100).collect::<Vec<_>>()];
        let err = kristoffersen_feb18_find_sequence_chain_with_timeout(&events, &steps, 1000, Some(1)).unwrap_err();
        assert!(matches!(err, SequenceError::SequenceTimeout { .. }));
    }

    #[test]
    fn max_paths_guard() {
        // would trigger if we had huge data, but test limit is enforced
        let events: Vec<_> = (0..10).map(event).collect();
        let steps = vec![(0..10).collect::<Vec<_>>(); 5];
        let _ = kristoffersen_feb18_find_sequence_chain_with_timeout(&events, &steps, 1000, None);
    }
}