<!-- \[CLASSIFICATION] -->

<!-- NSM-FPP-20260219-001 — TASK-005 v1 -->

<!-- SPDX-License-Identifier: MIT -->



\# sigma-eval



Deterministic, capability-poor Sigma subset evaluator for validating detection rules against

synthetic timelines produced by `timeline-builder`.



\## Supported Sigma subset (baseline)



\- YAML fields: `title`, `logsource`, `detection`

\- `detection`:

&nbsp; - One or more named selections (e.g., `selection`, `selection1`, ...)

&nbsp; - Each selection is a mapping of field matchers (AND semantics)

&nbsp; - Supported matcher forms:

&nbsp;   - `Field: value` (equals; case-insensitive)

&nbsp;   - `Field|contains: value` (case-insensitive substring)

&nbsp;   - `Field|startswith: value` (case-insensitive prefix)

&nbsp;   - `Field|endswith: value` (case-insensitive suffix)

&nbsp; - Legacy boolean `condition` supports:

&nbsp;   - selection identifiers

&nbsp;   - `and`, `or`

&nbsp;   - parentheses



\## Sequence detection extension (TASK-005)



\### Syntax



```yaml

detection:

&nbsp; selection1:

&nbsp;   EventID: 4688

&nbsp;   Image|endswith: "powershell.exe"

&nbsp; selection2:

&nbsp;   EventID: 5156

&nbsp;   Application|contains: "powershell"

&nbsp; sequence:

&nbsp;   - selection1

&nbsp;   - selection2

&nbsp; timeframe: 5s



