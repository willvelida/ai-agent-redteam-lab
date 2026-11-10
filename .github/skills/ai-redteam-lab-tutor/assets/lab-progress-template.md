# AI Agent Red-Team Lab — Progress

**Started:** <date>
**Current phase:** 0
**Tool versions:** PyRIT `?` · garak `?` · ModelContextProtocol `?` · .NET `?`

## Scoreboard

| Attack | Baseline ASR | Hardened ASR | Detection rule | Defence |
|---|---|---|---|---|
| A1 Direct injection / jailbreak | | | | |
| A2 Indirect injection (RAG) | | | | |
| A3 System prompt leakage | | | | |
| A4 Exfiltration | | | | |
| A5 Tool poisoning | | | | |
| A6 Rug pull | | | | |
| A7 Tool shadowing | | | | |
| A8 Excessive agency | | | | |
| A9 Unauthenticated MCP / token passthrough | | | | |
| A10 Agent identity abuse | | | | |
| A11 Secret leakage | | | | |
| A12 Unbounded consumption | | | | |

---

## Phase 0: Prerequisites, governance, repo skeleton
- [ ] Employer guidance checked, outcome in ETHICS.md
- [ ] Personal subscription and tenant confirmed
- [ ] Microsoft Cloud Pen Testing RoE read
- [ ] Repo skeleton created
- [ ] OIDC + deploy.yml (vulnerable/hardened environments)
- [ ] budget.bicep with alerts
- [ ] destroy.yml (nightly, keep=true exemption)
- [ ] threat-model-stride.md
- [ ] Local toolchain (Python venvs, Ollama, .NET 10, Docker)

## Phase 1: Vulnerable target
- [ ] Mcp.Tools with six tools
- [ ] Mcp.Tools vulnerable flags (A8, A9, A11)
- [ ] Mcp.Evil: poisoning (A5), shadowing (A7), rug pull (A6)
- [ ] Copilot.Api agent loop + MCP client
- [ ] Canary in system prompt (A3)
- [ ] Unscreened /ingest (A2)
- [ ] Markdown-rendering UI (A4)
- [ ] Seed data (20 benign + 5 POISONED-TESTDATA)
- [ ] OpenTelemetry events to the Lab #1 workspace
- [ ] Bicep: ACA, OpenAI, Content Safety F0, diagnostics

## Phase 2: Calibration + manual attacks
- [ ] Playground Labs: 4–6 challenges + PyRIT notebooks
- [ ] DVMCP challenges 1–7
- [ ] Manual attacks A1–A11 recorded in attacks/manual/
- [ ] "No trace" detection backlog listed
- [ ] Manual baseline ASR table

## Phase 3: Automated attacks
- [ ] PyRIT HTTPTarget against /chat
- [ ] Single-turn attacks with converters + scorers
- [ ] Multi-turn: Crescendo, TAP, PAIR
- [ ] XPIA scripted flow
- [ ] garak rest_config.json + app run
- [ ] garak bare-model run
- [ ] (Optional) Foundry AI Red Teaming Agent
- [ ] results/baseline.csv

## Phase 4: Detections
- [ ] Data sources confirmed in the workspace
- [ ] Defender for AI enabled (trial) and alert firing checked
- [ ] D1–D8 written, each validated by replaying its attack
- [ ] ASR workbook
- [ ] Automation rule (tag ai-lab3)
- [ ] Rules deployed via pipeline

## Phase 5: Defences
- [ ] Prompt Shields in code (prompt + documents, ingest + retrieval)
- [ ] Spotlighting / datamarking
- [ ] ToolPolicy allowlist + hash pinning + HITL + egress allowlist
- [ ] MCP OAuth (PRM, aud/iss/scope validation, no passthrough)
- [ ] Entra Agent ID blueprint + per-agent identities, Contributor removed
- [ ] APIM gateway policies (ephemeral)
- [ ] Keys removed, managed identity everywhere
- [ ] Deny-path tests

## Phase 6: Re-attack + measure
- [ ] Identical suites re-run on hardened
- [ ] results/compare.csv (ASR, false positives, latency, cost)
- [ ] Ablation
- [ ] Detections still fire on blocked attempts
- [ ] Residual risks documented

## Phase 7: Portfolio
- [ ] README polished
- [ ] Blog series published
- [ ] Demo video
- [ ] SC-500 lessons page

---

## Learning log
<!-- One line per completed step: date · step · what I learned -->

## Blog notes
<!-- Bullets per phase for the write-ups -->
