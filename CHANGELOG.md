# Changelog

## [1.2.3] - 2024-06-20
### Fixed
- DNS exfil buffer overflow (NSM-2024-0145)
- ETW patch instability on Win11 24H2

### Added
- Indirect syscall support for beacon-core
- JA3 spoofing for TLS exfil
## [1.3.0] - 2026-02-16

### Added
- **ETW Patching Module** (`edr-evasion/src/etw_patch.rs`)
  - Three techniques: syscall, memory patching, IAT hooking
  - Extensive OPSEC comments with EDR version testing references
  
- **AMSI Bypass Module** (`edr-evasion/src/amsi_bypass.rs`)
  - AMSI patching stub with multiple implementation paths
  - PowerShell v2.0 installation detection utility
  
- **Test Suite** (`edr-evasion/tests/`)
  - Unit tests for ETW patch module
  - Unit tests for AMSI bypass module
  - Test module exports via mod.rs
  
- **Integration Test** (`tests/test_full_chain.rs`)
  - Full attack chain simulation
  - Prerequisite verification tests
