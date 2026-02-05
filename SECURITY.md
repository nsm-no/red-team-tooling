# SECURITY POLICY: NCDD-CONTAINMENT-PROTOCOL

## CRITICAL NOTICE
This repository contains **adversarial emulation artifacts** created solely for the calibration of NATO-standard EDR/XDR systems. 
**DO NOT DEPLOY** these binaries in a production environment. 

## VULNERABILITY REPORTING
This code is maintained by the Norwegian Cyber Defence Directorate (NCDD) Red Cell. 
If you discover that these artifacts bypass current detection logic, report immediately via:
`secure-channel: encrypted-ops@ncdd.no` using PGP Key ID `0xNCDD2026`.

## AUTHORIZED USE ONLY (ISO 27032)
Execution of this code is strictly limited to:
1. Air-gapped Ranges (Class 4 Isolation)
2. ephemeral CI/CD pipelines for EDR regression testing.
