# STRENGT FORTROLIG – TS
# NSM Mandate 2026 §4.2 – Dual-Use Technology Controls
# Derived From: Mandate 2026 §3.1
# Declassify On: 20360214 or official derogation
# Access: Air-gapped systems only. TS clearance required.

## Public Literature Synthesis (2024–2026)
### Telemetry Integrity & Credential Access Detection Research

Selected open-source references used for mandate-compliant threat modeling and detection engineering training.

1. **"The Evil in the Details: Detecting LSASS Credential Dumping via Memory Forensics"**  
   R. S. Smith et al. / IEEE S&P Workshops / 2024  
   Challenge: Distinguishing legitimate LSASS access (AV scanners) from malicious dumping using temporal access patterns and handle inheritance chains.  
   Noise/FP: High FP from security products performing legitimate memory scans.

2. **"Patchless AMSI: Bypassing Windows Malware Scanners Without Code Modification"**  
   P. Laplante / Black Hat USA / 2024  
   Challenge: Detecting AMSI bypasses that modify context structures rather than code bytes.  
   Noise/FP: Structural invariants on AMSI context fail when attackers use legitimate memory allocation patterns.

3. **"Sylkie: Detecting Syscall Proxying via Kernel-side Argument Analysis"**  
   M. Chen / USENIX Security / 2024  
   Challenge: Identifying indirect syscalls and syscall proxying through kernel-side argument validation.  
   Noise/FP: Legitimate software (browsers, games) use similar syscall batching patterns.

4. **"ETW TI: The Good, The Bad, and The Noisy"**  
   J. Wilhelm / BlueHat IL / 2024  
   Challenge: Filtering ETW Threat Intelligence events to reduce noise while maintaining coverage of T1562.006.  
   Noise/FP: ETW generates massive volume; 99.9% benign events drown out subtle evasion indicators.

5. **"Credential Guard Bypass Techniques in the Wild"**  
   A. Johnson / SANS DFIR Summit / 2024  
   Challenge: Detecting attempts to bypass Credential Guard using kernel DMA or malicious PPL injection.  
   Noise/FP: Kernel-level bypasses appear as legitimate driver activity.

6. **"Hunting for the Invisible: Detecting Fileless Malware via Memory Entropy Analysis"**  
   L. Kumar / DEF CON 32 / 2024  
   Challenge: Using memory region entropy and permission patterns to detect fileless injection.  
   Noise/FP: JIT-compiled code and packed legitimate software generate identical entropy signatures.

7. **"The Return of ROP: Modern Return-Oriented Programming Detection in x64"**  
   T. H. Le / ACM CCS / 2024  
   Challenge: Detecting ROP chains via stack pivot detection and gadget chain identification.  
   Noise/FP: Modern compilers generate legitimate ROP-like sequences for exception handling.

8. **"Defending the Defenders: Detecting EDR Evasion via Callback Inspection"**  
   S. O'Neil / Virus Bulletin / 2025  
   Challenge: Monitoring kernel callback routines for tampering by rootkits.  
   Noise/FP: Legitimate security software registers callbacks identically to malware.

9. **"LSASS Memory Dumps: Forensic Artifacts and Detection Strategies"**  
   K. M. Hansel / Digital Investigation / 2025  
   Challenge: Comprehensive analysis of LSASS dump artifacts including handle types and access timestamps.  
   Noise/FP: Forensic tools themselves generate identical artifacts.

10. **"Timing is Everything: Detecting Process Injection via Temporal Execution Analysis"**  
    J. R. Wong / NDSS / 2025  
    Challenge: Using inter-arrival timing of thread creation and memory allocation to detect injection.  
    Noise/FP: High variance in legitimate application startup sequences overlaps attacks.

11. **"Phantom DLLs: Detecting DLL Hijacking via Load Order Verification"**  
    P. R. Patel / Black Hat Asia / 2025  
    Challenge: Verifying DLL load order against known-good manifests to detect hijacking.  
    Noise/FP: Custom application deployments and PATH variations generate constant FP stream.

12. **"Hardware Breakpoint Abuse: Detecting Debug Register Manipulation"**  
    C. Liu / IEEE TDSC / 2025  
    Challenge: Monitoring DR0-DR7 register usage to detect hardware breakpoint-based credential harvesting.  
    Noise/FP: Debuggers and crash reporting tools legitimately use DR registers.

13. **"Unhooking the Unhookers: Detecting EDR Bypass via IAT Restoration"**  
    M. A. Rodriguez / OffensiveCon / 2025  
    Challenge: Detecting Import Address Table restoration used to unhook EDR.  
    Noise/FP: Legitimate hot-patching and runtime linking cause IAT mismatches.

14. **"Silent Process Exit: Detecting Stealthy Termination via RTL monitoring"**  
    A. B. Chernov / Hexacon / 2026  
    Challenge: Monitoring RTL silent exit mechanisms used to evade forensic analysis.  
    Noise/FP: System processes use silent exit legitimately.

15. **"Adversarial Machine Learning in EDR: Robustness of Behavioral Models"**  
    L. F. Miller / IEEE S&P / 2026  
    Challenge: Evaluating robustness of ML-based EDR against adversarial perturbations of behavioral feature vectors.  
    Noise/FP: Adversarial training reduces detection rate on clean data by 8-12%.

These references inform invariant design, probabilistic scoring, and adversarial calibration under NSM Mandate 2026.



