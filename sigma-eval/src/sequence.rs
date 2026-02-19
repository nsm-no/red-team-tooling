// [CLASSIFICATION]
// NSM-FPP-20260219-001 — TASK-005 v1
// SPDX-License-Identifier: MIT
// NOTE: This file is capability-poor; pure sequence evaluation. No I/O, no network, no process execution.

use timeline_builder::model::TimelineEvent;

/// Parse timeframe strings to microseconds.
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
pub fn kristoffersen_feb18_parse_timeframe_to_us(s: &str) -> Result<i64, String> {
    let raw = s.trim();
    if raw.is_empty() {
        return Err("timeframe must be non-empty".to_string());
    }

    // Determine suffix
    let (num_part, mult): (&str, i64) = if let Some(prefix) = raw.strip_suffix("ms") {
        (prefix, 1_000) // ms -> us
    } else if let Some(prefix) = raw.strip_suffix('s') {
        (prefix, 1_000_000) // s -> us
    } else if let Some(prefix) = raw.strip_suffix('m') {
        (prefix, 60 * 1_000_000) // m -> us
    } else {
        return Err("timeframe must end with one of: ms, s, m".to_string());
    };

    let n_str = num_part.trim();
    if n_str.is_empty() {
        return Err("timeframe numeric value missing".to_string());
    }

    // Integer-only for determinism.
    let n: i64 = n_str
        .parse::<i64>()
        .map_err(|_| "timeframe numeric value must be an integer".to_string())?;

    if n < 0 {
        return Err("timeframe must be non-negative".to_string());
    }

    // Prevent overflow (conservative)
    let us = n
        .checked_mul(mult)
        .ok_or_else(|| "timeframe too large".to_string())?;

    Ok(us)
}

/// Find earliest deterministic sequence chain within timeframe.
///
/// Inputs:
/// - `events`: full timeline events
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
    events: &[TimelineEvent],
    step_indices: &[Vec<usize>],
    timeframe_us: i64,
) -> Option<Vec<usize>> {
    if step_indices.is_empty() {
        return None;
    }

    // If any step has zero matches, no chain can exist.
    for v in step_indices {
        if v.is_empty() {
            return None;
        }
    }

    // Precompute per-step cursors for linear scanning
    // For each start candidate in step 0, attempt to build chain.
    for &start_idx in &step_indices[0] {
        let t0 = events.get(start_idx)?.ts_unix_micros;

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
            }
        }

        if ok {
            // Verify last timestamp within timeframe (defensive)
            let last_ts = events.get(*chain.last().unwrap())?.ts_unix_micros;
            if last_ts - t0 <= timeframe_us {
                return Some(chain);
            }
        }
    }

    None
}

fn find_next_after_within(
    events: &[TimelineEvent],
    candidates: &[usize],
    prev_idx: usize,
    t0: i64,
    timeframe_us: i64,
) -> Option<usize> {
    let prev_ts = events.get(prev_idx)?.ts_unix_micros;
    let deadline = t0.saturating_add(timeframe_us);

    for &idx in candidates {
        let ts = events.get(idx)?.ts_unix_micros;

        // Ensure ordered after prev in deterministic (ts, idx) ordering
        let after_prev = (ts > prev_ts) || (ts == prev_ts && idx > prev_idx);
        if !after_prev {
            continue;
        }

        // Timeframe bound from start
        if ts > deadline {
            // Since candidates are sorted by (ts, idx), no later candidate can satisfy.
            return None;
        }

        return Some(idx);
    }

    None
}
