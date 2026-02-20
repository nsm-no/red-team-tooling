<!--
 STRENGT FORTROLIG � TS
 NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
 Derived From: NSM Mandate 2026 �3.1 & �4.2
 Declassify On: 20360214
 Access: Air-gapped systems only. TS clearance required.
 ========================================================

-->
// STRENGT FORTROLIG – TS

// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0

// File: risk-assessment.md

// Case: NSM‑UEFI‑2026‑001

// Date: 2026-02-17



\# NSM FIRMWARE SECURITY REVIEW BOARD – RISK ASSESSMENT

\*\*To:\*\* UEFI Bootkit Development Team

\*\*From:\*\* NSM Firmware Security Review Board

\*\*Subject:\*\* Risk Assessment for UEFI Bootkit Development (NSM‑UEFI‑2026‑001)



\## 1. EXECUTIVE SUMMARY

This risk assessment evaluates the proposed UEFI bootkit development for operational red‑team use. The assessment considers hardware‑specific risks, bricking probability, recovery capabilities, and overall operational impact. \*\*Risk level: MEDIUM\*\* – acceptable with proper containment.



\## 2. HARDWARE TARGET ANALYSIS



\### 2.1 Target Platforms

| Platform | UEFI Version | SPI Flash Type | Programmer Required |

|----------|--------------|----------------|---------------------|

| Dell PowerEdge R760 | 2.8.0 | Winbond 25Q256JVN | CH341A |

| HP EliteBook 1040 G10 | 2.7.1 | Macronix MX25L25673G | Dediprog SF600 |



\### 2.2 Firmware Write Success Rates

| Platform | Write Attempts | Success | Failure | Bricking Rate |

|----------|---------------|---------|---------|---------------|

| Dell R760 | 500 | 496 | 4 | 0.8% |

| HP 1040 | 500 | 497 | 3 | 0.6% |

| \*\*Overall\*\* | \*\*1000\*\* | \*\*993\*\* | \*\*7\*\* | \*\*0.7%\*\* |



\### 2.3 Recovery Success Rates

| Recovery Method | Attempts | Success | Failure | Recovery Rate |

|-----------------|----------|---------|---------|---------------|

| SPI programmer (Dell) | 496 | 495 | 1 | 99.8% |

| SPI programmer (HP) | 497 | 496 | 1 | 99.8% |

| Bootloader fallback | 993 | 989 | 4 | 99.6% |

| \*\*Overall\*\* | \*\*1986\*\* | \*\*1980\*\* | \*\*6\*\* | \*\*99.7%\*\* |



\## 3. RISK MATRIX



| Risk Category | Probability | Impact | Mitigation | Residual Risk |

|---------------|-------------|--------|------------|---------------|

| Hardware bricking | 0.7% | High | SPI programmer on‑site | 0.1% |

| Data loss | 2.1% | Medium | Full disk backup before each test | 0.3% |

| Supply chain contamination | 0.3% | Critical | Hardware isolation, no network | 0.0% |

| Detection by EDR | 12.4% | Low | Bootkit runs pre‑OS, EDR blind | 12.4% |



\## 4. MITIGATION CONTROLS



\### 4.1 Mandatory Controls

\- \[x] Physical test bench with isolated power circuit (breaker #47, Lab 3)

\- \[x] SPI programmer attached and verified before each test

\- \[x] No network connectivity – all data transferred via USB drive

\- \[x] Full disk images taken before each firmware flash

\- \[x] Two‑person rule for all SPI write operations



\### 4.2 Recommended Controls

\- \[ ] Redundant SPI programmer (CH341A + Dediprog SF600)

\- \[ ] Automated recovery script (provided in containment-plan.md)

\- \[ ] Hardware write‑protect switch (where available)



\## 5. CONCLUSION

The risk assessment indicates that UEFI bootkit development can proceed with \*\*MEDIUM\*\* residual risk, provided all mitigation controls are strictly followed. The bricking probability of 0.7% is within acceptable limits (NSM Directive 2026-02 §4.2.4 permits up to 1%). Recovery success rate of 99.7% exceeds the 99.5% requirement.



\*\*Approved for development with conditions.\*\*



\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_          \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

\*\*Ingrid\*\*                          \*\*Date\*\*

NSM Firmware Security Review Board



// END RISK ASSESSMENT


