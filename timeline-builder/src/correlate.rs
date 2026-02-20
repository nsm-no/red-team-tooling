// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// timeline-builder/src/correlate.rs
// NSM-20260218-002

use crate::time::KristoffersenFeb18Rng;

/// FNV-1a 64-bit (std-only) for stable seed derivation.
pub fn kristoffersen_feb18_fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in data {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// scenario_seed = FNV1a64(seed || scenario_id || normalized_params)
pub fn kristoffersen_feb18_derive_scenario_seed(
    base_seed: u64,
    scenario_id: &str,
    params_norm: &str,
) -> u64 {
    let mut buf = Vec::with_capacity(8 + scenario_id.len() + params_norm.len());
    buf.extend_from_slice(&base_seed.to_le_bytes());
    buf.extend_from_slice(scenario_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(params_norm.as_bytes());
    kristoffersen_feb18_fnv1a64(&buf)
}

/// Deterministic â€œGUID-likeâ€ string derived from seed + labels.
/// Format: 8-4-4-4-12 hex (synthetic, not real UUID v4).
pub fn kristoffersen_feb18_guid(seed: u64, label: &str) -> String {
    let mut buf = Vec::with_capacity(8 + label.len());
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(label.as_bytes());
    let h1 = kristoffersen_feb18_fnv1a64(&buf);
    let h2 = kristoffersen_feb18_fnv1a64(&[buf.as_slice(), b":2"].concat());

    // Build 128 bits from two 64-bit hashes
    let a = h1;
    let b = h2;

    let p1 = (a >> 32) as u32;
    let p2 = (a >> 16) as u16;
    let p3 = (a) as u16;
    let p4 = (b >> 48) as u16;
    let p5 = b & 0x0000_FFFF_FFFF_FFFF;

    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        p1, p2, p3, p4, p5
    )
}

pub fn kristoffersen_feb18_hex64(seed: u64, label: &str) -> String {
    let mut buf = Vec::with_capacity(8 + label.len());
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(label.as_bytes());
    let h = kristoffersen_feb18_fnv1a64(&buf);
    format!("0x{:016x}", h)
}

/// Deterministic per-scenario host-local sequence.
pub struct Sequence {
    rng: KristoffersenFeb18Rng,
    n: u64,
}

impl Sequence {
    pub fn new(seed: u64) -> Self {
        Self { rng: KristoffersenFeb18Rng::new(seed), n: 0 }
    }

    pub fn next_label(&mut self, prefix: &str) -> String {
        self.n += 1;
        let salt = self.rng.next_u64();
        format!("{}:{}:{:016x}", prefix, self.n, salt)
    }
}

