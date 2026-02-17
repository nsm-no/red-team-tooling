\# EfiGuard UEFI Bootkit



\*\*Classification:\*\* STRENGT FORTROLIG // TS  

\*\*Mandate Validation:\*\* NSM Directive 2026-02 §4.2 (Dual-Use Technology Controls)  

\*\*Directive Hash:\*\* f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0  

\*\*Firmware Security Review Board Approval:\*\* NSM-FSRB-2026-007 (Valid through 2026-03-19)  



\## Overview



EfiGuard is a production-grade UEFI bootkit for Windows 11 24H2 that provides firmware-level persistence before the OS, survives disk wipes, and delivers kernel-mode payloads with absolute stealth. It incorporates cutting-edge research and real-world APT techniques while adding novel capabilities.



\## Capabilities



\- \*\*Four-stage patching pipeline\*\* for complete boot process control

&nbsp; - Boot Manager patching (bypass signature validation)

&nbsp; - Winload patching (disable VBS/HVCI)

&nbsp; - Kernel patching (disable PatchGuard and DSE)

&nbsp; - Runtime service hooking (hide malicious variables)

\- \*\*Multiple delivery methods\*\*

&nbsp; - In-memory injection (most stealthy)

&nbsp; - Disk-based staging (fallback)

&nbsp; - Network retrieval (advanced)

\- \*\*Secure Boot bypass\*\* via multiple techniques

&nbsp; - Shim-based attack

&nbsp; - Bootloader vulnerability exploitation

&nbsp; - Machine Owner Key injection

\- \*\*Complete anti-forensics\*\*

&nbsp; - Runtime service hooking to hide traces

&nbsp; - Kernel-level stealth after payload delivery

&nbsp; - Anti-analysis checks for virtual environments



\## Build Requirements



\- Windows 10/11 development system (air-gapped)

\- EDK2 build environment (tested with edk2-stable2025)

\- Visual Studio 2019 Community Edition

\- NSM Code Signing Key (GPG key `696FBA48886C3F16`)

\- Physical test hardware with SPI programmer for recovery



\## Build Instructions



1\. Verify air-gapped environment:

&nbsp;  ```cmd

&nbsp;  ./verify\_authority --mandate NSM-mandate-2026 --toolset uefi-bootkit

