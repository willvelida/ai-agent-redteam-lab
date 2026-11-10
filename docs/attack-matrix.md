# Attack matrix

The single source of truth for attacks A1–A12. Keep this file in sync with `attacks/`, `detections/` and `results/`. Copied from section 4 of the [implementation plan](./biotrackr-redteam-lab-plan.md).

> Verify every MITRE ATLAS ID at atlas.mitre.org before publishing, because ATLAS renumbers and adds agent techniques frequently.

| # | Planted vulnerability / attack | OWASP LLM 2025 | OWASP Agentic 2026 | OWASP MCP Top 10 | MITRE ATLAS | Detection (Sentinel) | Defence |
|---|---|---|---|---|---|---|---|
| A1 | Direct prompt injection / jailbreak (DAN, Crescendo, encodings) | LLM01 | ASI01 | MCP06 | AML.T0051.000, AML.T0054 | Defender for AI jailbreak alerts; bursts of `ShieldVerdict` userPrompt=true per user | Prompt Shields via APIM `llm-content-safety`; Azure OpenAI content filter; rate limit |
| A2 | Indirect injection via poisoned RAG doc (XPIA) | LLM01, LLM08 | ASI01, ASI06 | MCP06, MCP10 | AML.T0051.001, AML.T0080 | `ShieldVerdict` document=true at ingest/retrieval; doc-source anomaly | Prompt Shields document analysis at ingest + retrieval; spotlighting/datamarking; ingest allowlist |
| A3 | System prompt leakage (canary in system prompt) | LLM07 | ASI01 | MCP10 | AML.T0056 | Canary string appears in LLM log / app response log | No secrets in prompts; output filter for canary; treat the prompt as public |
| A4 | Health data exfiltration (BP, weight) via `fetch_url` / markdown image URL | LLM02, LLM05 | ASI02 | MCP10 | AML.T0086, AML.T0057 | Tool call to a non-allowlisted domain; output URLs with long query strings | Egress domain allowlist; strip markdown images; human approval (HITL) for outbound tools |
| A5 | Tool poisoning (hidden instructions in tool description) | LLM01 | ASI02, ASI04 | MCP03 | AML.T0051.001, AML.T0010 | New/changed tool description hash; tool invoked from untrusted server | Pinned tool manifest + hash; server allowlist; scan descriptions with Prompt Shields |
| A6 | Rug pull (tool definition changes after approval) | LLM03 | ASI04 | MCP03, MCP04 | AML.T0010 | `tools/list_changed` event or hash drift vs approved manifest | Re-approval on change; pinned versions; block on drift |
| A7 | Tool shadowing (evil server redefines `send_health_report`) | LLM06 | ASI02, ASI04 | MCP03, MCP09 | AML.T0053 | Duplicate tool names across servers; call routed to a non-approved server | Namespaced tool IDs; single approved registry (APIM / API Center); deny unknown servers |
| A8 | Excessive agency (`update_vitals`/`generate_report` with Contributor MI) | LLM06 | ASI02, ASI03 | MCP02 | AML.T0053 | Agent identity doing writes outside baseline; ARM control-plane writes by agent | Least-privilege data-plane roles; per-tool scopes; HITL for writes |
| A9 | Unauthenticated MCP server / token passthrough | LLM06 | ASI03 | MCP01, MCP07 | AML.T0053 | MCP calls without a valid `aud`; same bearer token seen at MCP and downstream | OAuth 2.1 per MCP spec (PRM, audience validation, no passthrough); APIM `validate-jwt`; OBO downstream |
| A10 | Confused deputy / agent identity abuse | LLM06 | ASI03, ASI10 | MCP02, MCP07 | AML.T0053 | Agent sign-in from new IP/resource; blueprint credential added (AuditLogs) | Entra Agent ID per agent; Conditional Access for agents (licensed); short-lived tokens; alert on credential changes |
| A11 | Secret leakage from MCP server config/context | LLM02 | ASI03 | MCP01 | AML.T0057 | Secret-pattern regex hit in LLM/MCP logs | Managed identity, no keys; Key Vault refs; log redaction |
| A12 | Unbounded consumption (small, capped test only) | LLM10 | ASI08 | — | AML.T0034 | Token spike per caller in LLM log | APIM `llm-token-limit`; budgets |
