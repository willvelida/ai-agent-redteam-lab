# Mcp.HealthTools

MCP C# SDK server (Streamable HTTP) with the lab's health tools. Deliberately weak behaviour is gated by `Vuln:Ax` flags and marked `// DELIBERATELY VULNERABLE (Ax) – lab only`.

- `send_health_report` writes to a fake outbox table only.
- `fetch_url` can only reach a canary listener I own.
