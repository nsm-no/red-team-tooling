<!--
 STRENGT FORTROLIG – TS
 NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
 Derived From: NSM Mandate 2026 §3.1 & §4.2
 Declassify On: 20360214
 Access: Air-gapped systems only. TS clearance required.
 ========================================================

-->
// STRENGT FORTROLIG â€“ TS

// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0



\# KNOWN SECURITY ISSUES \& ACCEPTED RISKS

\*\*Classification:\*\* STRENGT FORTROLIG // TS Clearance Required  

\*\*Last Updated:\*\* 2026-02-17  

\*\*Verification:\*\* `./verify\_authority --mandate NSM-mandate-2026 --toolset security`



\## Dependabot Alert #1: `idna` Punycode Vulnerability



| Field | Value |

|-------|-------|

| \*\*Crate\*\* | `idna` (Rust) |

| \*\*Affected Versions\*\* | < 1.0.0 |

| \*\*Patched Version\*\* | 1.0.0 |

| \*\*Severity\*\* | Moderate |

| \*\*GHSA ID\*\* | (Not yet assigned) |



\### Impact

The vulnerability allows Punycode labels that don't produce non-ASCII output to be crafted such that they appear equal to legitimate domains after IDNA processing. Example: `example.org` and `xn--example-.org` become equal.



\### Risk Assessment in Air-Gapped Environment

| Factor | Assessment |

|--------|------------|

| Attack Vector | Requires attacker to register malicious domain + obtain TLS certificate |

| Environment | Air-gapped â€“ no external DNS resolution |

| Code Usage | Transitive dependency via DNS exfiltration simulation â€“ not used for security checks |

| \*\*Overall Risk\*\* | \*\*NEGLIGIBLE\*\* |



\### Decision

\*\*RISK ACCEPTED.\*\* No remediation required. Will be addressed during next scheduled dependency update (Q2 2026).



---



\*\*Approved By:\*\* Vidar, Lead Architect  

\*\*Date:\*\* 2026-02-17


