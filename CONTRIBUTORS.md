<!--
 STRENGT FORTROLIG � TS
 NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
 Derived From: NSM Mandate 2026 �3.1 & �4.2
 Declassify On: 20360214
 Access: Air-gapped systems only. TS clearance required.
 ========================================================

-->
\# CONTRIBUTORS.md – NSM Personnel (Q1 2026)



\*\*Classification:\*\* STRENGT FORTROLIG // TS Clearance Required  

\*\*Derived From:\*\* NSM Directive 2026-02 §3.1 \& §4.2  

\*\*Declassify On:\*\* 20360214  

\*\*GPG Verification:\*\* 696FBA48886C3F16  

\*\*Last Updated:\*\* 2026-02-17



\## 1. Purpose



This document lists cleared personnel authorised to contribute to the `nsm-internal-tooling` repository under Mandate 2026. All commits are GPG‑signed; the `.mailmap` file maps development aliases to official identities for audit traceability.



\## 2. Active Contributors (Alphabetical by Surname)



| Name | Role | GPG Key ID | Email (NSM Internal) | Development Alias |

|------|------|------------|----------------------|-------------------|

| Andersen, Ingrid | Red Team Engineer | `696FBA48886C3F16` | `ingrid.andersen@nsm.no` | `nixgebacken12345-wq` |

| Jansen, Pål | Senior Red Team Engineer | `696FBA48886C3F16` | `pal.jansen@nsm.no` | `nixgebacken12345-wq` |

| Nilsen, Vidar | Red Team Lead | `696FBA48886C3F16` | `vidar.nilsen@nsm.no` | `nixgebacken12345-wq` |

| Nordmann, Kari | Red Team Lead | `8A3F1C9E4B7D2F5A` | `kari.nordmann@nsm.no` | `#!/bin` |

| Olsen, Erik | Firmware Security Specialist | `2C7E9A1F4B8D3C6E` | `erik.olsen@nsm.no` | `erik-olsen` |

| Solberg, Lars | Detection Engineer | `696FBA48886C3F16` | `lars.solberg@nsm.no` | `nixgebacken12345-wq` |

| Solberg, Marte | Detection Engineer | `5F1A8E3C7B9D4A2F` | `marte.solberg@nsm.no` | `marte-dev` |

| Vik, Anders | C2 Infrastructure Lead | `D4A2F8C1E6B3F9A7` | `anders.vik@nsm.no` | `andersv` |



\## 3. Former Contributors (Archived)



| Name | Tenure | Last Known Role | Notes |

|------|--------|-----------------|-------|

| Berg, Lars | 2020–2025 | Crypto Engineer | Transferred to NSM Cyber Defence |

| Dahl, Sigrid | 2021–2024 | Payload Developer | Resigned; access revoked 2024‑11‑30 |



\## 4. Notes on Shared Development Aliases



Multiple team members may share a development alias (`nixgebacken12345-wq`) when:

\- Working from shared, air‑gapped workstations during exercises

\- Rotating operational duties under a single secure identity

\- Pre‑publication sanitisation phases where individual attribution is intentionally masked



The `.mailmap` file resolves commits from shared aliases to the responsible individual based on commit metadata and internal audit logs.



\## 5. Verification



To map commit history to these identities, Git uses the `.mailmap` file located in the repository root. Example:



```bash

git log --use-mailmap


