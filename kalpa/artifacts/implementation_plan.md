# Implementation Plan - KALPA: Causal Cyber Reasoning System for AI Kavach

KALPA is an autonomous Cyber Reasoning System (CRS) designed for high-stakes defense environments (AI Kavach). It integrates static analysis, dynamic fuzzing, LLM-based causal reasoning, patch synthesis, security contract compilation, and a self-adversarial validation loop to discover vulnerabilities, patch root causes, compile durable security contracts, and prove fix robustness with zero human intervention.

## User Review Required

> [!IMPORTANT]
> **LLM Provider & Tooling Modes**: KALPA features a dual-execution strategy:
> 1. **Live Autonomous Mode**: Connects to LLM APIs (e.g. OpenAI / Anthropic / Gemini or local OpenAI-compatible endpoints) and local static/fuzzing tools (`semgrep`, `bandit`, `pytest`, `AFL++`/custom sanitizing fuzzers).
> 2. **Standalone / Offline Mode**: Includes built-in rule-based & LLM fallback reasoning engines with simulated/native static-dynamic harnesses so the CRS can run out-of-the-box in offline or air-gapped defense environments without external API keys if needed.

> [!NOTE]
> All mandatory user-specific rules (SQLAlchemy `expunge_all()`, SQLite UTC-naive datetimes, File-Polling `(st_mtime, st_size)` signature tracking) will be strictly baked into KALPA's core and reference target services.

## Proposed System Architecture & Components

```
                    +------------------------------------+
                    |  Target Ingestion & Code Slicing   |
                    +-----------------+------------------+
                                      |
                                      v
                    +------------------------------------+
                    |  Static & Dynamic Analysis / Fuzz  |
                    |   (SARIF, Sanitizers, POV Inputs)  |
                    +-----------------+------------------+
                                      |
                                      v
                    +------------------------------------+
                    |    KALPA Causal Reasoning Engine   |
                    |     (Root Cause & Causal Graph)    |
                    +-----------------+------------------+
                                      |
                                      v
                    +------------------------------------+
                    | Patch & Security Contract Compiler |
                    | (Code Diffs + Assertions & Oracles)|
                    +-----------------+------------------+
                                      |
                                      v
                    +------------------------------------+
                    | Self-Adversarial Validation Loop   |
                    |  (Regression Tests & Refuzzing)    |
                    +-----------------+------------------+
                                      |
                                      v
                    +------------------------------------+
                    |     Evidence Bundle & Report       |
                    | (POVs, Diffs, Contracts, Metrics)  |
                    +------------------------------------+
```

---

### Phase 1: Concept Design, Metrics & System Core Framework

#### [NEW] [kalpa/__init__.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/__init__.py)
Package initialization and metadata export for `kalpa`.

#### [NEW] [kalpa/config.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/config.py)
Configuration management for resource budgets (max fuzz time, max LLM calls, memory/CPU caps), tool paths, and environment settings.

#### [NEW] [kalpa/models.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/models.py)
Data models and dataclasses: `VulnerabilityReport`, `POV`, `CausalExplanation`, `CausalNode`, `CandidateIntervention`, `SecurityContract`, `PatchResult`, `EvidenceBundle`, and `MetricsTracker`. Includes SQLite UTC-naive normalization helper according to user rules.

---

### Phase 2: Toolchain Setup (Static & Dynamic Analysis, Fuzzing)

#### [NEW] [kalpa/static_analysis/sarif_parser.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/sarif_parser.py)
Parses standard SARIF static analysis reports (Semgrep, Bandit, CodeQL, Clang SA).

#### [NEW] [kalpa/static_analysis/analyzer.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/analyzer.py)
Orchestrates static analysis execution, code slicing, call graph extraction, and vulnerability candidate prioritization.

#### [NEW] [kalpa/dynamic_analysis/fuzzer.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/fuzzer.py)
Automated harness generation and multi-protocol dynamic fuzzing (HTTP payload mutation, function arguments, buffer mutation) with crash & sanitizer stack trace capturing.

#### [NEW] [kalpa/dynamic_analysis/pov_generator.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/pov_generator.py)
Generates and confirms reproducible Proof-of-Vulnerability (POV) payloads and triggers.

---

### Phase 3: KALPA Causal Reasoning Engine (LLM Brain)

#### [NEW] [kalpa/causal_engine/prompts.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/prompts.py)
Structured prompts for causal root-cause analysis, control/data flow tracing, and intervention ranking.

#### [NEW] [kalpa/causal_engine/reasoner.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/reasoner.py)
The core LLM Brain that ingests static findings, dynamic traces, and code slices to build the Causal Graph JSON, identify root causes, and formulate intervention strategies.

---

### Phase 4: Patch Synthesis & Security Contract Compiler

#### [NEW] [kalpa/patching/synthesizer.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/patching/synthesizer.py)
Synthesizes minimal, clean unified code diffs targeting root causes while preserving original style and functionality.

#### [NEW] [kalpa/contract_compiler/compiler.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/compiler.py)
Compiles security knowledge into executable security contracts:
1. Code assertions (`assert_safe_input`, boundary checks)
2. Unit & Integration test cases (`test_security_contract_*.py`)
3. Dynamic fuzzing oracles (safety invariant monitors)

---

### Phase 5: Self-Adversarial Validation Loop & Orchestration

#### [NEW] [kalpa/orchestrator/controller.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/orchestrator/controller.py)
The central CRS controller managing:
`Intake -> SAST -> Dynamic POV -> Causal Analysis -> Patch & Contract Synthesis -> Test Build -> Adversarial Refuzz -> Accept/Reject Loop`.
Handles rollback on failure, token budget tracking, and iteration limits.

#### [NEW] [kalpa/utils/file_watcher.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/utils/file_watcher.py)
Daemon file watcher implementation adhering strictly to user rules: tracks `(st_mtime, st_size)` in `_file_seen_signature: Dict[str, tuple]` to prevent duplicate processing.

---

### Phase 6: Benchmark Targets, CLI Entrypoint & Evidence Bundling

#### [NEW] [run_kalpa.py](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/run_kalpa.py)
Single-command CLI entrypoint script for KALPA autonomous execution.

#### [NEW] [run_kalpa.sh](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/run_kalpa.sh)
Bash wrapper script for single-command deployment.

#### [NEW] [targets/vulnerable_service/](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/targets/vulnerable_service/)
Target web microservice featuring multiple real-world vulnerability classes (SQL Injection with SQLAlchemy read methods adherence, Buffer/Length boundary issue, Path Traversal, Auth Bypass) with regression test suites.

#### [NEW] [README.md](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/README.md)
Comprehensive technical documentation detailing KALPA's architecture, AI Kavach vision, installation, CLI usage, design decisions, and benchmarks.

#### [NEW] [CHANGELOG.md](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/CHANGELOG.md)
Detailed changelog documenting initial implementation milestones, architecture, and features.

---

## Verification Plan

### Automated Tests
- Execute full unit and integration test suite: `python -m unittest discover -s tests -p "test_*.py"`
- Test target service vulnerabilities before and after running `run_kalpa.py` on benchmark targets.
- Verify security contracts are auto-generated and successfully pass regression + adversarial refuzzing.
- Validate generated evidence bundles (`evidence_bundles/<target_name>/`).

### Manual & E2E Verification
- Run `python run_kalpa.py --target targets/vulnerable_service --output-dir evidence_bundles/output`
- Verify log outputs, metrics summary, patch diffs, security contracts, and evidence bundles.
