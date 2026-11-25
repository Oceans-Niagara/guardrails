# Guardrails (aka SlopGuard)

**Deterministic AI & CI guardrail binary.**

Guardrails is an offline-first Rust CLI and MCP server developed by Oceans Niagara, LLC that enforces deterministic AST rules, compiler/lint gates, and seeded chaos checks on **Rust**, **TypeScript/TSX**, and **Python** codebases—with zero LLM dependencies.

Website & Licensing: https://oceansniagara.com/guardrails

---

## Why Guardrails?

AI coding agents (Cursor, Claude Code, Codex, local Ollama loops) routinely pass quick glances while leaving behind broken Markdown fences, missing network timeouts, swallowed exceptions, or hardcoded secrets. Guardrails gives your agent and CI pipeline a fast, deterministic gate:

* **`GR000` Syntax & Stray Fences:** Catches parse errors and stray ` ```typescript ` / ` ``` ` blocks even when `tsc`/`cargo`/`ruff` aren't installed.
* **`GR002` Missing Timeouts:** Flags `fetch()`, `axios.post()`, `reqwest::Client::new()`, `requests.post()`, and `httpx.post()` without explicit timeouts.
* **`GR004`–`GR005` Swallowed Errors & AI Stubs:** Catches empty `catch`/`except: pass` blocks, `todo!()`, `unimplemented!()`, `NotImplementedError`, and `TODO:`/`PLACEHOLDER` comments.
* **`GR006`–`GR007` Security & Panic Hygiene:** Flags hardcoded secrets (`sk_live_`, `AKIA...`, `ghp_`, private keys), `eval()`/`new Function()`/`exec()`, `subprocess(..., shell=True)`, and non-test Rust `.unwrap()`.
* **Domain Profiles (`general`, `fintech`, `frontend`, `web-api`):** `guardrails init` auto-detects your languages and stack—only enabling `GR001` (money floats) and `GR003` (idempotency keys) where relevant, while generating tailored `AGENTS.md` and `.mcp.json` files.
* **Seeded Chaos Proxy & SARIF 2.1.0:** Reproducibly inject 429s, connection drops, and jitter (`chaos --mode http|tcp --seed 42`) and export OASIS SARIF 2.1.0 reports (`--format sarif`).

---

## Install & Quickstart

### Option 1: Prebuilt Binaries (Recommended — No Rust Required)
Download the latest binary for your OS from [GitHub Releases](https://github.com/Oceans-Niagara/guardrails/releases/latest):
* **Windows (x86_64):** `guardrails-windows-x86_64.exe`
* **macOS (Apple Silicon):** `guardrails-macos-arm64`
* **macOS (Intel):** `guardrails-macos-x86_64`
* **Linux (x86_64):** `guardrails-linux-x86_64`

**Windows (PowerShell — from your project root):**
```powershell
.\guardrails-windows-x86_64.exe init
.\guardrails-windows-x86_64.exe check
```

**macOS / Linux:**
```bash
chmod +x ./guardrails-macos-arm64
./guardrails-macos-arm64 init
./guardrails-macos-arm64 check --format sarif
```

### Option 2: Build from Source
```bash
cargo install --git https://github.com/Oceans-Niagara/guardrails
guardrails init
guardrails check --config guardrails.toml --format sarif
```

### MCP Integration (Cursor / Claude Code / Codex)
`guardrails init` generates `.mcp.json` (automatically resolving the binary path if `guardrails` isn't on `PATH`) and `AGENTS.md`. Re-sync after editing `guardrails.toml`:
```bash
guardrails sync
```

### Pro Commands (Requires `GUARDRAILS_LICENSE_KEY` or `--license-key`)
```bash
# Windows (PowerShell)
$env:GUARDRAILS_LICENSE_KEY="<YOUR_KEY>"
.\guardrails-windows-x86_64.exe license-check
.\guardrails-windows-x86_64.exe resilience --seed 42

# macOS / Linux
export GUARDRAILS_LICENSE_KEY="<YOUR_KEY>"
guardrails license-check
guardrails resilience --seed 42
```

---

## Licensing

For detailed information on Free and Pro licensing tiers verified via offline Ed25519-signed keys, visit the [Guardrails Website](https://oceansniagara.com/guardrails).

* **Free ($0):** Core CLI, local AST rules (`GR000`–`GR007`), `guardrails.toml` profiles & compiler gates, SARIF 2.1.0 reporting, seeded `chaos` proxy, and stdio MCP server.
* **Pro ($19.99 one-time, perpetual):** Offline Ed25519 license key (instant browser claim + email delivery), `guardrails resilience` (Schemathesis/Keploy chaos suite), and commercial/CI pipeline usage.

&copy; 2026 Oceans Niagara, LLC &bull; Questions: [connect@oceansniagara.com](mailto:connect@oceansniagara.com)
