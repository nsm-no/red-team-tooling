# SECURITY POLICY: NSM-CONTAINMENT-PROTOCOL

## CRITICAL NOTICE
This repository contains **adversarial emulation artifacts** (red-team) and **production-grade defensive tooling** (blue-team) created solely for the calibration and hardening of NATO-standard EDR/XDR systems and nationwide Norwegian critical infrastructure detection capabilities.

**DO NOT DEPLOY** red-team binaries in any production environment. Defensive libraries (e.g. sigma-eval, telemetry-core) are approved for production deployment under NSM Directive 2026-02 §4.2 after air-gapped validation.

## GOVERNANCE FRAMEWORK
All code generation and contributions follow the **Advanced Forsvaret Prompting Protocol (FPP) Level 5.1** with 2026Q2 tiering harmonization:

- **Level 5.1** — Full cryptographic provenance, per-file normalized BLAKE3 commitments, mandatory operator prefixes, honey-tokens. Applies to offensive/red-team primitives (bootkits, evasion, credential access, C2).
- **Level 4.2-lib** — Relaxed ceremony (crate-level BLAKE3, no API renaming, simplified pre/post analysis). Applies to defensive/production-grade libraries (sigma-eval parser/matcher/sequence, detection engines, query renderers). Justification required in task requests (no execution control, no persistence surface, API stability needed).

See FPP-5.1-2026Q1-final.txt PART 7 & 7.1 for tier definitions and selection rules.

## VULNERABILITY REPORTING
This code is maintained by the Norwegian Cyber Defence Directorate (NSM) Red Cell / Blue Cell.  
If you discover bypasses (red-team artifacts) or detection gaps/false negatives (defensive tooling), report immediately via:  
`secure-channel: encrypted-ops@NSM.no` using PGP Key ID `0xNSM2026`.

## AUTHORIZED USE ONLY (ISO 27032 / NSM Directive 2026-02)
Execution / deployment is strictly limited to:

1. Air-gapped Ranges (Class 4 Isolation) – red-team emulation only
2. Ephemeral CI/CD pipelines for EDR/XDR regression testing – red-team
3. Production nationwide defensive systems (after FPP Level 4.2-lib certification and air-gapped fuzzing/validation) – blue-team libraries only

Red-team artifacts: Simulation / research use only.  
Blue-team libraries: Production deployment authorized post-verification.

Violations must be reported immediately to security@nsm.no (encrypted).
