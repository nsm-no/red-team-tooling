<!--
 STRENGT FORTROLIG � TS
 NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
 Derived From: NSM Mandate 2026 �3.1 & �4.2
 Declassify On: 20360214
 Access: Air-gapped systems only. TS clearance required.
 ========================================================

-->
# STRENGT FORTROLIG – TS
# NSM Mandate 2026 §4.2 – Dual-Use Technology Controls
# Derived From: Mandate 2026 §3.1
# Declassify On: 20360214 or official derogation
# Access: Air-gapped systems only. TS clearance required.

## 7-Step Mandate-Compliant Defensive Evolution Roadmap

This roadmap outlines the progressive hardening of telemetry and credential-access detection capabilities under NSM Mandate 2026 governance.

| Step | Phase                          | Estimated FP Reduction | Key Research Gap                              | Engineering Focus                              | Timeline     | Key Metrics / Deliverables                     |
|------|--------------------------------|------------------------|-----------------------------------------------|------------------------------------------------|--------------|------------------------------------------------|
| 1    | Prefix Heuristics             | Baseline (15–25%)      | Obfuscation resilience                        | YARA rules, IOC databases                      | 1–3 months  | TPR 75%, FPR 15%, Latency <1ms                 |
| 2    | Invariant Modeling            | +40–60%                | Data-only attack detection                    | Binary analysis, CFG reconstruction            | 3–9 months  | TPR 85%, FPR 8%, 6–8 invariants                |
| 3    | Probabilistic Scoring         | +20–40%                | Optimal weight calibration without labels     | Weighted linear combination, threshold tuning  | 6–12 months | AUC 0.89, Mean score 0.45 ± 0.20               |
| 4    | Temporal Sequences            | +15–30%                | Real-time Markov training in air-gapped env   | Bigram/trigram models, sequence alignment      | 9–15 months | 15 states, Transition accuracy 94%             |
| 5    | Bayesian Updating             | +10–25%                | Online prior adaptation from classified data  | Streaming inference, belief tracking           | 12–18 months| Posterior convergence in 5 observations         |
| 6    | Formal Verification           | +10–20% (soundness)    | Scalable SMT encoding for x86-64 binaries     | Z3/CBMC proofs on invariant properties         | 18–24 months| Verified bounds [0.1, 0.9], Proof time <10s    |
| 7    | Adversarial Monte Carlo       | +15–35% (robustness)   | Efficient adversarial example generation      | PGD/FGSM attacks + weight recalibration        | 24+ months  | Certified robust 85% cases (ε=0.15)            |

**Overall Evolution Path:**
- **Year 1**: Foundation (Steps 1–3) – move from brittle signatures to statistical robustness
- **Year 2**: Intelligence (Steps 4–5) – add temporal and belief reasoning
- **Year 3+**: Assurance (Steps 6–7) – achieve formal guarantees and adversarial resilience

This progression aligns with NSM Mandate 2026 dual-use controls and prioritizes defensive integrity evolution while maintaining air-gapped containment.




