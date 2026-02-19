<!-- NSM-20260218-002 -->



\# sigma-eval



Deterministic, capability-poor Sigma subset evaluator for validating detection rules against

synthetic timelines produced by `timeline-builder`.



\## Supported Sigma subset



\- YAML fields: `title`, `logsource`, `detection`

\- `detection`:

&nbsp; - One or more named selections (e.g., `selection`, `selection1`, ...)

&nbsp; - Each selection is a mapping of field matchers

&nbsp; - Supported matcher forms:

&nbsp;   - `Field: value` (equals)

&nbsp;   - `Field|contains: value` (case-insensitive substring)

&nbsp; - `condition` supports:

&nbsp;   - selection identifiers

&nbsp;   - `and`, `or`

&nbsp;   - parentheses



\## API



\- `kristoffersen\_feb18\_evaluate(timeline: \&Timeline, sigma\_rule\_yaml: \&str) -> EvalResult`



\## Example



Run:



```bash

cargo run -p sigma-eval --example eval\_timeline



