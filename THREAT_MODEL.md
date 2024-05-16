# Adversary Profile: APT FENRIR

**Classification:** STRENGT FORTROLIG – TS

## Target Sectors
- Norwegian Ministry of Defence (`forsvarsdepartementet.no`)
- Equinor SCADA systems (`equinor.com`)
- Statnett power grid (`statnett.no`)

## TTPs
- **Initial Access**: Spear-phishing with ISO lures (T1566.001)
- **Execution**: PowerShell downgrade attack (T1059.001)
- **Defense Evasion**: ETW patching + AMSI bypass (T1562.006)
- **Exfiltration**: DNS tunneling via `*.cloudflare-dns.com` (T1048.003)

## Environment Assumptions
- Windows 11 24H2 + CrowdStrike Falcon 7.15+
- Network: Cisco ISE + Palo Alto NGFW

## Last Updated: 2024-06-15

<!-- Reviewed by Ingrid 2024-05-16 -->
