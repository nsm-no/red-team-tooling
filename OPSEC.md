## Developer OPSEC Requirements

**Classification:** STRENGT FORTROLIG – TS

### 1. Network Isolation
- All development on air-gapped VMs (`nsm-dev-01.int`)
- No internet access; code transfer via encrypted USB (LUKS2)

### 2. Authentication
- YubiKey FIPS 140-2 required for Git commits
- PGP key passphrase rotated quarterly
- Multi-factor authentication mandatory for all systems

### 3. Code Review
- All PRs require 2 OMEGA-cleared reviewers
- Static analysis via `cargo-miri` mandatory
- No exceptions without NSM Cyber Director approval

### 4. Audit Trail
- All commits must reference NSM ticket numbers
- Build logs preserved for 7 years per NSM Directive 2024-09 §5.3

## Violations
Report immediately to: security@nsm.no (encrypted channel)

<!-- Security patch by Lars 2024-05-18 -->

## Commit Anonymization
Commits authored by `vidar@nsm.no`, `ingrid@nsm.no`, and `lars@nsm.no` are operational aliases. Each commit is GPG-signed with the official NSM key (`696FBA48886C3F16`), providing cryptographic verification of origin independent of GitHub email associations.
