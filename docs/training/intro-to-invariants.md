// STRENGT FORTROLIG – TS

// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0



\# INTRODUCTION TO STRUCTURAL INVARIANTS

\*\*Classification:\*\* STRENGT FORTROLIG // TS Clearance Required  

\*\*Author:\*\* Lars (Detection Engineering)  

\*\*Last Updated:\*\* 2026-02-17  

\*\*Prerequisites:\*\* None (but familiarity with Windows internals helps)



\## 1. WHAT IS A STRUCTURAL INVARIANT?



A \*\*structural invariant\*\* is a property of a system that must remain constant for the system to be considered "healthy." In the context of endpoint detection, we define invariants for critical OS structures that attackers often modify to evade detection.



\*\*Examples:\*\*

\- The ETW provider table's function pointers should never point to a trampoline.

\- The kernel callback list should never be unhooked.

\- The system call table should never be modified.



\## 2. WHY INVARIANTS?



Traditional signature-based detection can be bypassed by obfuscation. Behavioral detection can be evaded by mimicking legitimate behavior. \*\*Structural invariants\*\* are harder to bypass because they rely on the system's underlying architecture, which attackers cannot easily change without leaving traces.



\## 3. THE 8 CORE INVARIANTS



| # | Name | What It Checks | MITRE ATT\&CK |

|---|------|----------------|--------------|

| 1 | Provider Registration | Call chain of `EtwEventRegister` | T1562.006 |

| 2 | Provider Table Integrity | Function pointers in `EtwProviderTable` | T1562.006 |

| 3 | Event Write Call Site | Code at `EtwEventWrite` call sites | T1562.006 |

| 4 | Provider Reference Count | Reference count of ETW providers | T1562.006 |

| 5 | Session Activity Pattern | Temporal Markov chain of ETW sessions | T1562.006 |

| 6 | Provider Unload | Call chain of `EtwEventUnregister` | T1562.006 |

| 7 | Buffer Management | Allocation sizes of ETW buffers | T1562.006 |

| 8 | Kernel Callback Registration | `ObRegisterCallbacks` count | T1562.006 |



\## 4. HOW INVARIANTS ARE IMPLEMENTED



In Rust, we use the `windows` crate to access kernel structures and validate them. Example (simplified):



```rust

pub struct ProviderTableIntegrity {

&nbsp;   expected\_signatures: \[u8; 16],

}



impl ProviderTableIntegrity {

&nbsp;   pub fn validate(\&self, function\_ptr: \*const u8) -> bool {

&nbsp;       let buffer = unsafe { std::slice::from\_raw\_parts(function\_ptr, 16) };

&nbsp;       buffer == self.expected\_signatures

&nbsp;   }

}

