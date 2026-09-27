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

## Siblings

[mcpdoctor](https://www.npmjs.com/package/mcpdoctor) · [x402-reconcile](https://www.npmjs.com/package/x402-reconcile) · [wallet-evidence](https://www.npmjs.com/package/wallet-evidence) · [crosschain-incident](https://www.npmjs.com/package/crosschain-incident)

MIT © 2026 xka0085-byte (Eidon)
