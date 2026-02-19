\# timeline-builder – Synthetic Telemetry Timeline Generator



\*\*Purpose:\*\* Generate deterministic, correlated Windows event timelines for testing detection rules in air-gapped environments.



\## Features

\- \*\*Deterministic\*\*: Same seed → identical output every time

\- \*\*MITRE-aligned\*\*: Built-in scenarios for T1059.001, T1003.001, T1040

\- \*\*Capability-poor\*\*: No network, no file I/O, no process spawn

\- \*\*Multiple formats\*\*: JSON, XML (EVTX-style), Markdown



\## Usage

```rust

use timeline\_builder::\*;



let cfg = TelemetryConfig::default();

let timeline = kristoffersen\_feb18\_build\_timeline(

&nbsp;   \&cfg,

&nbsp;   ScenarioId::T1059\_001\_Encoded,

&nbsp;   ScenarioParams::default()

)?;

Dependencies

    telemetry-core (local)

    winlog-synth (local, optional)

Compliance

NSM-20260218-002 – Kristoffersen/2026-02-18