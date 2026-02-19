// timeline-builder/src/time.rs
// NSM-20260218-002

/// Deterministic PRNG (xorshift64*). std-only.
#[derive(Clone)]
pub struct KristoffersenFeb18Rng {
    state: u64,
}

impl KristoffersenFeb18Rng {
    pub fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 0x9e3779b97f4a7c15 } else { seed };
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    pub fn range_u32(&mut self, low: u32, high_inclusive: u32) -> u32 {
        if low >= high_inclusive {
            return low;
        }
        let span = (high_inclusive - low) as u64 + 1;
        let v = (self.next_u64() % span) as u32;
        low + v
    }
}

/// Deterministic monotonic timestamp builder with microsecond jitter.
pub struct MonotonicClock {
    t: i64, // unix micros
    rng: KristoffersenFeb18Rng,
}

impl MonotonicClock {
    /// Start time is deterministic: epoch micros + deterministic offset derived from scenario seed.
    pub fn new(scenario_seed: u64) -> Self {
        // Base: 2026-02-18T00:00:00Z as unix seconds: 1771372800 (fixed constant)
        // NOTE: This constant is purely to anchor synthetic timelines and is not from wall-clock at runtime.
        const BASE_UNIX_SECS_2026_02_18: i64 = 1771372800;
        let base = BASE_UNIX_SECS_2026_02_18 * 1_000_000;

        let mut rng = KristoffersenFeb18Rng::new(scenario_seed ^ 0xA5A5_F0F0_1234_5678);
        let offset_secs = (rng.next_u64() % (6 * 3600)) as i64; // within 6 hours
        let offset_micros = (rng.next_u64() % 1_000_000) as i64;

        Self {
            t: base + offset_secs * 1_000_000 + offset_micros,
            rng,
        }
    }

    /// Advance by `base_ms` plus deterministic micro-jitter, returning the new timestamp.
    pub fn step(&mut self, base_ms: u32, jitter_max_us: u32) -> i64 {
        let jitter = self.rng.range_u32(0, jitter_max_us);
        self.t += (base_ms as i64) * 1_000 + (jitter as i64);
        self.t
    }

    pub fn now(&self) -> i64 {
        self.t
    }
}
