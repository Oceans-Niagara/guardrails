# Guardrails (aka SlopGuard)

**Deterministic AI & CI guardrail binary.**

Guardrails is an offline-first Rust CLI and MCP server by Oceans Niagara, LLC that enforces deterministic AST rules, compiler/lint gates, and seeded chaos checks on **Rust**, **TypeScript/TSX**, and **Python** codebases—with zero LLM dependencies.

Website & Licensing: https://oceansniagara.com/guardrails

## What It Catches

* **`GR000` Syntax & Stray Fences:** Flags parse errors and stray ` ``` ` Markdown blocks even without `tsc`/`cargo`/`ruff`.
* **`GR002` Missing Timeouts:** Catches `fetch`, `axios`, `reqwest`, `requests`, and `httpx` calls without explicit timeouts.
* **`GR004`–`GR005` Swallowed Errors & Stubs:** Flags empty `catch`/`except: pass` blocks, `todo!()`, `NotImplementedError`, and `TODO:`/`PLACEHOLDER` comments.
* **`GR006`–`GR007` Security & Panics:** Detects hardcoded secrets (`sk_live_`, `AKIA`, `ghp_`, private keys), `eval`/`exec`/`shell=True`, and non-test Rust `.unwrap()`.
* **Auto-Detected Profiles (`general`, `fintech`, `frontend`, `web-api`):** `init` detects your stack, enables `GR001`/`GR003` (money floats & idempotency) only where relevant, and generates `.mcp.json` + `AGENTS.md`.
* **Chaos & SARIF:** Seeded HTTP/TCP fault proxy (`chaos --seed 42`) and OASIS SARIF 2.1.0 output (`--format sarif`).

## Install & Quickstart

**Prebuilt Binaries (Recommended — No Rust Required):** Download from [GitHub Releases](https://github.com/Oceans-Niagara/guardrails/releases/latest) (`guardrails-windows-x86_64.exe`, `guardrails-macos-arm64`, `guardrails-macos-x86_64`, `guardrails-linux-x86_64`).

```powershell
# Windows (PowerShell — from your project root)
.\guardrails-windows-x86_64.exe init
.\guardrails-windows-x86_64.exe check
```

```bash
# macOS / Linux (swap binary name for your OS/arch)
chmod +x ./guardrails-macos-arm64
./guardrails-macos-arm64 init
./guardrails-macos-arm64 check --format sarif
```

```bash
# Or build from source
cargo install --git https://github.com/Oceans-Niagara/guardrails
guardrails init && guardrails check --format sarif
```

Re-sync `.mcp.json` and `AGENTS.md` anytime after editing `guardrails.toml` with `guardrails sync`.

## Licensing

Offline Ed25519-verified tiers (see the [Guardrails Website](https://oceansniagara.com/guardrails)):

* **Free ($0):** Core CLI, AST rules (`GR000`–`GR007`), `guardrails.toml` gates, SARIF 2.1.0 output, `chaos` proxy, and stdio MCP server.
* **Pro ($19.99 one-time, perpetual):** Offline Ed25519 license key (`license-check`), `guardrails resilience` automated fault-injection suite, and commercial/CI usage.

&copy; 2026 Oceans Niagara, LLC &bull; [connect@oceansniagara.com](mailto:connect@oceansniagara.com)
