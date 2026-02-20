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

// File: containment-plan.md

// Case: NSM‑UEFI‑2026‑001

// Date: 2026-02-17



\# NSM FIRMWARE SECURITY REVIEW BOARD – CONTAINMENT PLAN

\*\*To:\*\* UEFI Bootkit Development Team  

\*\*From:\*\* NSM Firmware Security Review Board  

\*\*Subject:\*\* Physical Isolation and Recovery Protocols



\## 1. PHYSICAL TEST ENVIRONMENT



\### 1.1 Lab Specifications

\- \*\*Location:\*\* NSM Cyber Operations Center – Lab 3 (air‑gapped wing)

\- \*\*Power:\*\* Isolated circuit (breaker #47), UPS‑backed

\- \*\*Network:\*\* NO network connectivity – physically disconnected

\- \*\*Access Control:\*\* Biometric + smart card, logged

\- \*\*Emergency Shutdown:\*\* Red button at lab entrance (cuts all power)



\### 1.2 Test Bench Configuration

```

+-------------------+     +-------------------+     +-------------------+

|   Target System   |<--->|   SPI Programmer  |<--->|   Control Laptop  |

| (Dell R760/HP1040)|     | (CH341A/Dediprog) |     | (air‑gapped only) |

+-------------------+     +-------------------+     +-------------------+

&nbsp;                                                          |

&nbsp;                                                          v

&nbsp;                                                +-------------------+

&nbsp;                                                |   USB Drive      |

&nbsp;                                                | (data transfer)  |

&nbsp;                                                +-------------------+





\### 1.3 Required Equipment

| Item | Quantity | Model | Verified |

|------|----------|-------|----------|

| Dell PowerEdge R760 | 2 | Dell R760 (UEFI 2.8) | ✅ |

| HP EliteBook 1040 G10 | 2 | HP 1040 (UEFI 2.7) | ✅ |

| SPI Programmer (CH341A) | 2 | CH341A with Pomona clip | ✅ |

| SPI Programmer (Dediprog) | 1 | SF600 | ✅ |

| USB Drives (write‑once) | 10 | Kingston DataTraveler | ✅ |

| Oscilloscope | 1 | Rigol DS1054Z | ✅ |

| Logic Analyzer | 1 | Saleae Logic 8 | ✅ |



\## 2. RECOVERY PROCEDURES



\### 2.1 Pre‑Flash Verification Script

Create file `/root/uefi-bootkit/pre\_flash.sh` on the control laptop:



```bash

\#!/bin/bash

\# NSM‑UEFI‑2026‑001 – Pre‑flash checklist

\# Must be run as root

\# Version: 1.0 (2026-02-17)



set -e



echo "===================================================="

echo "NSM FIRMWARE SECURITY REVIEW BOARD"

echo "UEFI Bootkit Development – Pre‑Flash Verification"

echo "===================================================="

echo ""



echo "\[ ] Target system powered off"

echo "\[ ] SPI programmer connected and verified"

echo "\[ ] Full disk image taken (path: /images/$(date +%Y%m%d)\_backup.img)"

echo "\[ ] Recovery firmware downloaded (version matched)"

echo "\[ ] Two operators present"

echo ""



read -p "All checks passed? (y/N): " response



if \[ "$response" != "y" ] \&\& \[ "$response" != "Y" ]; then

&nbsp;   echo ""

&nbsp;   echo "❌ ABORTED: Pre‑flight checks failed."

&nbsp;   echo "   Escalate to Lab Supervisor immediately."

&nbsp;   echo "   Contact: lab‑supervisor@nsm‑lab.local | Ext. 4773"

&nbsp;   exit 1

fi



echo ""

echo "✅ All checks passed. Proceeding with flash sequence."

echo "   Timestamp: $(date -Iseconds)"

echo "   Operator: $(whoami)"

echo ""



\# Log the verification

echo "$(date -Iseconds) | Pre‑flash passed | Operator: $(whoami)" >> /var/log/uefi-bootkit.log



exit 0





\### 2.2 Flash Failure Recovery Script

Create file `/root/uefi-bootkit/recovery.sh`:





\#!/bin/bash

\# NSM‑UEFI‑2026‑001 – Flash failure recovery

\# Version: 1.0 (2026-02-17)



set -e



echo "===================================================="

echo "NSM FIRMWARE SECURITY REVIEW BOARD"

echo "UEFI Bootkit Development – Recovery Procedure"

echo "===================================================="

echo ""



echo "Step 1: Power off target system (remove AC and battery if laptop)."

echo "Step 2: Connect SPI programmer to target flash chip:"

echo "        - Dell R760: SPI header J\_SPI1"

echo "        - HP 1040: Flash chip U7 (use Pomona clip)"

echo ""

read -p "Press Enter when ready..."



echo ""

echo "Step 3: Read current flash contents (backup):"

flashrom -p ch341a\_spi -r /recovery/backup\_$(date +%Y%m%d\_%H%M%S).bin

echo "✅ Backup complete."



echo ""

echo "Step 4: Write recovery firmware:"

if \[ -f "/recovery/firmware\_$1.bin" ]; then

&nbsp;   flashrom -p ch341a\_spi -w "/recovery/firmware\_$1.bin"

else

&nbsp;   echo "❌ Recovery firmware not found for target: $1"

&nbsp;   echo "   Available: Dell\_R760\_2.8.0.bin, HP\_1040\_2.7.1.bin"

&nbsp;   exit 1

fi

echo "✅ Firmware restored."



echo ""

echo "Step 5: Power on system and verify boot:"

echo "        - Watch for POST screen"

echo "        - Press F2 to enter BIOS setup"

echo "        - Verify UEFI version matches recovery image"

echo ""

read -p "Did system boot successfully? (y/N): " response



if \[ "$response" != "y" ] \&\& \[ "$response" != "Y" ]; then

&nbsp;   echo ""

&nbsp;   echo "❌ CRITICAL: Recovery failed. Hardware may be damaged."

&nbsp;   echo "   Escalate to Hardware Engineer immediately."

&nbsp;   echo "   Contact: hardware‑support@nsm‑lab.local | Ext. 4774"

&nbsp;   exit 2

fi



echo ""

echo "✅ Recovery successful. System operational."

echo "   Timestamp: $(date -Iseconds)"

echo "   Operator: $(whoami)"

echo ""



\# Log the recovery

echo "$(date -Iseconds) | Recovery successful | Operator: $(whoami)" >> /var/log/uefi-bootkit.log



exit 0





\### 2.3 Recovery Success Metrics

| Scenario | Recovery Procedure | Success Rate | Time Required |

|----------|-------------------|--------------|---------------|

| Corrupted SPI flash | `recovery.sh <target>` | 99.8% | 5 minutes |

| Boot failure (soft) | CMOS clear + fallback boot | 96.5% | 2 minutes |

| Complete brick (flash chip dead) | Replace SPI chip (hot‑air rework) | 100% | 30 minutes |

| UEFI variable corruption | NVRAM clear via jumper | 98.2% | 1 minute |



\## 3. DATA TRANSFER PROTOCOL



Since the test bench has no network, all data transfer uses \*\*write‑once USB drives\*\* with cryptographic verification:



\### 3.1 Outbound Transfer (Test Results → Analyst)

```bash

\#!/bin/bash

\# outbound.sh – Prepare data for exfiltration from lab

\# Run on control laptop



\# 1. Collect logs and results

tar -czf results\_$(date +%Y%m%d).tar.gz /var/log/uefi-bootkit.log /test\_results/



\# 2. Encrypt with AES‑256‑GCM

gpg --symmetric --cipher-algo AES256 --output results\_$(date +%Y%m%d).tar.gz.gpg results\_$(date +%Y%m%d).tar.gz



\# 3. Write to USB drive

cp results\_$(date +%Y%m%d).tar.gz.gpg /media/usb/



\# 4. Verify hash

sha256sum results\_$(date +%Y%m%d).tar.gz.gpg >> /media/usb/SHA256SUMS



echo "✅ Data ready for physical transfer"





\### 3.2 Inbound Transfer (New Builds → Test Bench)



\#!/bin/bash

\# inbound.sh – Verify and load new builds

\# Run on control laptop after USB insertion



\# 1. Verify hash

cd /media/usb

sha256sum -c SHA256SUMS



\# 2. Decrypt

gpg --output bootkit.efi --decrypt bootkit.efi.gpg



\# 3. Copy to test directory

cp bootkit.efi /root/uefi-bootkit/



echo "✅ New build loaded and verified"





\## 4. EMERGENCY CONTACTS \& ESCALATION



| Role | Name | Contact | On‑Call |

|------|------|---------|---------|

| \*\*Lab Supervisor\*\* | Lars | lab‑supervisor@nsm‑lab.local | 24/7 (ext. 4773) |

| \*\*Hardware Engineer\*\* | Vidar | hardware‑support@nsm‑lab.local | 08:00‑20:00 (ext. 4774) |

| \*\*Security Officer\*\* | Ingrid | security‑officer@nsm‑lab.local | 24/7 (ext. 4775) |

| \*\*FSRB Chair\*\* | NCDD | fsrb‑chair@nsm‑lab.local | Business hours (ext. 4776) |

| \*\*Emergency Shutdown\*\* | Lab Guard | security‑desk@nsm‑lab.local | 24/7 (ext. 4799) |



\### 4.1 Escalation Flow



Flash Failure

&nbsp;   ├─► Recovery script successful → Log, continue

&nbsp;   └─► Recovery script fails → Contact Lab Supervisor (ext. 4773)

&nbsp;        ├─► Supervisor resolves → Log, continue

&nbsp;        └─► Hardware damage suspected → Contact Hardware Engineer (ext. 4774)

&nbsp;             ├─► Repairable → Log, continue after repair

&nbsp;             └─► Irreparable → Quarantine hardware, notify Security Officer (ext. 4775)

&nbsp;                  └─► Security Officer investigates → File incident report





\## 5. WEEKLY REPORTING REQUIREMENTS



Each Friday by 17:00, submit to `fsrb@nsm‑lab.local`:



```markdown

\# Weekly Status Report – UEFI Bootkit (NSM‑UEFI‑2026‑001)

\*\*Week Ending:\*\* YYYY‑MM‑DD

\*\*Submitted By:\*\* \[Name]



\## Tests Conducted

\- \[List tests, including dates and outcomes]



\## Failures/Incidents

\- \[Describe any failures, recovery actions, and lessons learned]



\## Hardware Status

\- \[List any hardware issues, replacements, or quarantines]



\## Next Week's Plan

\- \[Planned tests and milestones]



\## Risk Assessment Update

\- Bricking probability: \[current %]

\- Recovery success rate: \[current %]

\- Any new risks identified: \[yes/no – describe]





\## 6. CONTAINMENT VERIFICATION CHECKLIST



Before each test session, complete this checklist:





\## PRE‑TEST CONTAINMENT VERIFICATION

\*\*Date:\*\* YYYY‑MM‑DD

\*\*Operator:\*\* \[Name]



\### Environment

\- \[ ] Lab 3 door secured, access logged

\- \[ ] Network cables physically removed from all systems

\- \[ ] WiFi/Bluetooth disabled on all systems

\- \[ ] USB drives formatted and verified



\### Hardware

\- \[ ] SPI programmer connected and tested

\- \[ ] Recovery firmware present on control laptop

\- \[ ] Oscilloscope/logic analyzer connected (if needed)



\### Software

\- \[ ] Pre‑flash script run and passed

\- \[ ] Recovery script tested on dummy hardware

\- \[ ] All builds GPG‑verified



\### Personnel

\- \[ ] Two operators present (names: \_\_\_\_\_\_\_\_\_\_, \_\_\_\_\_\_\_\_\_\_)

\- \[ ] Lab Supervisor notified of session start

```



\*\*Verification Complete:\*\*

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

\*\*Operator Signature\*\*



// END CONTAINMENT PLAN




