# oauthdoctor

Read-only **MCP OAuth discovery diagnostics**. One command tells you whether an MCP endpoint advertises its OAuth authorization metadata the way the [MCP Authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) expects an agent to discover it.

Part of the **Agent/Chain Evidence Tools** suite — CLI-first, read-only, no keys, no payments, JSON output.

## Quick start

```bash
npx oauthdoctor inspect https://mcp.example.com/mcp --json
```

## What it checks

- HTTP 401 challenge on unauthenticated request
- `WWW-Authenticate` header with `resource_metadata` parameter
- Protected Resource Metadata document (fetch + validate)
- `authorization_servers` → Authorization Server Metadata
- issuer / authorization endpoint / token endpoint presence and HTTPS
- PKCE `S256` code challenge method declaration

HTTP targets are refused except `127.0.0.1` / `localhost` / `::1` (fixture mode).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | PASS — all implemented discovery checks passed |
| `1` | FAIL — at least one implemented check failed (findings in JSON) |
| `2` | UNKNOWN — target could not be conclusively evaluated |
| `3` | usage error (bad arguments or non-HTTPS remote target) |

## NOT covered (explicitly)

- No login, no token exchange, no PKCE roundtrip, no refresh tokens
- No audience enforcement testing
- No credential storage or transmission
- A PASS is **not** an OAuth security certification — only that the observed discovery documents passed the implemented checks

## Status

Experimental (`0.1.0`). Local positive/negative fixture tests pass; a real public OAuth-protected MCP endpoint positive case has not yet been validated.

## Agent / Chain Evidence Tools — the suite

All tools are read-only, take no keys, and emit JSON.

| Tool | What it checks / proves | Try |
|---|---|---|
| [mcpdoctor](https://github.com/xka0085-byte/mcp-doctor) | x402 payment endpoint & MCP server preflight | `npx @eidonze/mcpdoctor` |
| [oauthdoctor](https://github.com/xka0085-byte/oauthdoctor) | MCP OAuth discovery diagnostics | `npx oauthdoctor` |
| [x402-reconcile](https://github.com/xka0085-byte/x402-reconcile) | x402 402-challenge inspector | `npx x402-reconcile` |
| [wallet-evidence](https://github.com/xka0085-byte/wallet-evidence) | Solana transaction evidence reports | `npx wallet-evidence` |
| [crosschain-incident](https://github.com/xka0085-byte/crosschain-incident) | cross-chain message incident normalization | `npx crosschain-incident` |
| [ReceiptRail](https://github.com/xka0085-byte/agenttoll) | on-chain x402 delivery receipts (Solana) | [live MCP endpoint](https://agenttoll-receipts.app.workbuddy.host/) |

Live tools page: <https://x402-endpoint-inspection.app.workbuddy.host/tools.html>

MIT © 2026 xka0085-byte (Eidon)
---

## Suite hub

Part of the [Agent / Chain Evidence Tools](https://xka0085-byte.github.io/evidence-tools/) suite — read-only, no-keys, no-payments diagnostics for AI agents on Web3.
