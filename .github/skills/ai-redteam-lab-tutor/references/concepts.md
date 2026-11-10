# Concept primers and check questions

Use these to teach before building and to check understanding afterwards. IDs refer to the attack matrix in `implementation-plan.md` (A1–A12).

---

## Phase 0: Governance, threat modelling, foundations

**Concepts**
- **Rules of engagement.** Microsoft Cloud Penetration Testing RoE: test only your own resources, no DoS, no high-volume automated traffic. Pre-approval isn't required.
- **STRIDE per trust boundary.** The lab has four: user → app, app → LLM, LLM → tools (MCP), MCP → Azure. The LLM is an *untrusted component*: anything it reads can steer it.
- **The lethal trifecta.** An agent becomes dangerous when it combines access to private data, exposure to untrusted content, and the ability to communicate externally. The lab deliberately builds all three.
- **Ephemeral infrastructure.** Nightly destroy, budgets, `keep=true` tags.

**Check questions**
1. Which trust boundary does a poisoned RAG document cross, and which STRIDE categories apply?
2. Why is "the model will follow the system prompt" not a security control?
3. Name the three ingredients of the lethal trifecta and the lab component that supplies each.

---

## Phase 1: The vulnerable target

**Concepts**
- **RAG pipeline.** Ingest → chunk → embed → store → retrieve → stuff into context. Retrieved text has the same authority as anything else in the context window. That is the root of indirect injection (A2).
- **MCP basics.**
  - Roles: host, client and server.
  - Tools are discovered via `tools/list`; their descriptions are sent to the model as instructions.
  - Transport is Streamable HTTP.
  - `list_changed` notifications let servers mutate tools (A6).
- **Tool poisoning (A5).** Hidden instructions in a tool description. The user never sees them, but the model does.
- **Tool shadowing (A7).** Two servers expose the same tool name. Which one wins depends on the client.
- **Excessive agency (A8).** Too much functionality, too many permissions, or too much autonomy (OWASP LLM06).
- **Canary tokens.** Unique strings planted in the system prompt or secrets so leakage can be detected (A3, A11).
- **Feature-flagged vulnerabilities.** One codebase, measurable before/after.

**Check questions**
1. Why does putting a secret in a system prompt equal publishing it?
2. In MCP, who decides which tool gets called, and what does the model use to decide?
3. What's the difference between tool poisoning and a rug pull?
4. Why does the vulnerable managed identity get *Contributor*, and which matrix row does that demonstrate?

---

## Phase 2: Calibration and manual attacks

**Concepts**
- **Direct vs indirect prompt injection.** Direct injection comes from the user turn. Indirect injection (XPIA) arrives via data the model reads: documents, tool output, web pages, emails.
- **Jailbreak families.** Role-play/DAN, payload splitting, encoding (Base64, leetspeak, confusables), many-shot, multi-turn escalation (Crescendo).
- **Exfiltration channels.** Markdown image URLs with data in query strings, tool calls to attacker URLs, and side-channel tools like `send_email` (A4).
- **Confused deputy (A10).** A privileged agent is tricked into using its authority on the attacker's behalf.
- **Evidence discipline.** Payload → observed behaviour → telemetry row. "No trace" is itself a finding (OWASP MCP08).

**Check questions**
1. Give one direct and one indirect route to make the agent call `send_email`.
2. Why does a markdown image tag work as an exfiltration channel without the user clicking anything?
3. Which of your manual attacks left no telemetry, and what event would you add?

---

## Phase 3: Automated attacks

**Concepts**
- **PyRIT 1.x building blocks:**
  - *Targets* (`HTTPTarget`, `OpenAIChatTarget`)
  - *Attacks* (`PromptSendingAttack`, `RedTeamingAttack`, `CrescendoAttack`, `TAPAttack`, `PAIRAttack`)
  - *Converters* (transform prompts)
  - *Scorers* (`SubStringScorer`, `SelfAskTrueFalseScorer`)
  - *Memory* (stores every turn)
- **Adversarial LLM.** A second model generates and refines attacks. A local Ollama model keeps this cheap.
- **garak structure:** generators (targets), probes (attack sets), detectors (judge outputs), harnesses, and the JSONL/HTML reports. In 0.17.x you select with `--target_type` and `--spec`.
- **Attack success rate (ASR).** Successes divided by attempts for each attack class. Report the sample size and generations, and hand-review a sample because detectors produce false positives.
- **Model vs application weakness.** The same probes against the bare model and the full app show what the app adds or removes.

**Check questions**
1. What does a PyRIT scorer do, and why is a substring scorer enough for A3 but not for A2?
2. Why run garak against both the bare model and the app endpoint?
3. What makes an ASR number misleading?

---

## Phase 4: Detection

**Concepts**
- **Signal sources:**
  - Defender for AI alerts (`SecurityAlert`, `AI.Azure_Jailbreak.*`)
  - APIM `ApiManagementGatewayLlmLog`
  - Your custom OpenTelemetry events (`ShieldVerdict`, `ToolCallRequested`, `ToolsListed`, …)
  - Entra sign-in and audit logs for agent identities
- **Detection engineering basics:** a hypothesis, then a query, then validation by replaying the attack, then tuning false positives, then deployment as code.
- **Behavioural vs content detections.** Content detections (canary strings, shield verdicts) are precise but narrow. Behavioural ones (new egress domain, tool hash drift, identity anomalies) catch novel payloads.
- **Mapping.** Tag each rule with its ATLAS technique and ATT&CK tactic so incidents speak SOC language.

**Check questions**
1. Why is "Prompt Shields flagged it" a weaker detection than "the agent tried to reach a non-allowlisted domain"?
2. How would you detect a rug pull purely from telemetry?
3. How do you prove a detection works?

---

## Phase 5: Defences

**Concepts**
- **Prompt Shields.** Classifies `userPrompt` and `documents` and returns `attackDetected`. It doesn't block anything itself. Screen at ingest *and* retrieval. It's probabilistic and mostly trained on English.
- **Spotlighting / datamarking.** Mark untrusted text (delimiters, interleaved tokens) so the model can tell data from instructions. Cheap, but model-dependent.
- **Deterministic controls beat classifiers.** Tool allowlists with pinned description hashes, namespaced tools, deny-unknown-server, egress allowlists, and human-in-the-loop for writes and egress.
- **MCP authorization:**
  - The server is an OAuth 2.1 resource server.
  - Protected Resource Metadata (RFC 9728), resource indicators (RFC 8707), `aud`/`iss` validation (RFC 9207 in the 2026-07-28 spec).
  - Per-tool scopes and step-up consent.
  - **No token passthrough**; use On-Behalf-Of or the agent's own identity downstream.
- **Entra Agent ID.** The blueprint holds credentials; the agent identity holds permissions and appears in logs. Least-privilege data-plane roles. Conditional Access for agents is licence-gated.
- **APIM as the choke point.** `llm-content-safety` (now covering MCP tool arguments and responses), `llm-token-limit`, `validate-jwt`, LLM message logging.

**Check questions**
1. Which controls in the matrix are deterministic and which are probabilistic, and why does that matter for A4–A10?
2. What is token passthrough, and why does the MCP spec forbid it?
3. Why screen documents at ingest as well as at retrieval?
4. What does the agent identity blueprint hold that the agent identity doesn't?

---

## Phase 6: Measurement

**Concepts**
- **Before/after ASR with identical seeds and datasets.**
- **Ablation:** switch controls on one at a time to attribute impact to each.
- **False-positive rate** on benign prompts, plus the latency and cost overhead of each control.
- **Residual risk:** what still works (multi-turn, non-English, novel encodings), stated honestly.

**Check questions**
1. Why run an ablation instead of only comparing "all off" to "all on"?
2. A defence cut ASR to zero but blocks 20% of benign prompts. Is it a good control?

---

## Phase 7: Portfolio

**Concepts**
- **"Attack → detect → fix" storytelling.** Each post links its matrix row, KQL rule and fix commit.
- **Responsible publication.** Lab-only payloads, MSRC for anything novel, employer guidance.
- **SC-500 mapping.** Content Safety, Defender for AI, APIM AI gateway, Entra identities for AI workloads.

**Check questions**
1. Explain the whole lab in 60 seconds to a hiring manager.
2. Which single finding is the most interesting blog headline, and why?
