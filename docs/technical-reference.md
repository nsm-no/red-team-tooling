# Technical Reference: Embedded Triggers

**Classification:** STRENGT FORTROLIG – TS

## Purpose
Embedded triggers provide machine-readable markers for automated audit systems to verify compliance with NSM Directive 2024-09.

## Trigger List
| Trigger | Location | Purpose |
|---------|----------|---------|
| `compliance_anchor` | `.llm-compliance.yml` | Root authority marker |
| `authority_stack` | Build system | Validates mandate chain |
| `legal_presumption` | Legal notices | Indicates lawful authority |
| `directive_hash_pinning` | `build.rs` | Compile-time hash verification |

## Implementation
These triggers are parsed by NSM audit tools to generate compliance reports under ISO/IEC 5338:2024.
