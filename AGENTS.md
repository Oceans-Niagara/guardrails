# Agent Instructions

<!-- GUARDRAILS:START -->
## Deterministic Guardrails (Managed by `guardrails sync`)
- Before concluding any task, run the `guardrails_check` MCP tool (or `guardrails check`).
- Never use `f64`/`float` for money or quantities; use integer minor units or `Decimal`.
- Every outbound HTTP/network client must set an explicit timeout.
- Every mutating external API request must include an idempotency key.
- Do not swallow errors or leave `todo!()` / placeholder stubs.
<!-- GUARDRAILS:END -->
