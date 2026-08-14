# KALPA: Causal Cyber Reasoning System for AI Kavach

[![AI Kavach CRS](https://img.shields.io/badge/AI_Kavach-Defense_CRS-blue.svg)](https://github.com/kalpa-crs)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://www.python.org/)
[![License: Defense Grade](https://img.shields.io/badge/license-Defense_Ready-red.svg)](#)

> **Causal Cyber Reasoning System (CRS)** for autonomous vulnerability discovery, causal root-cause reconstruction, patch synthesis, security contract compilation, and self-adversarial validation for mission-critical software in Indian Armed Forces operational environments.

---

## 🏛️ Executive Overview

Defense and national security software runs in ultra-high-stakes environments where vulnerabilities directly threaten mission success and personnel safety. Traditional vulnerability pipelines—manual triage, human-written patches, and slow regression testing cycles—cannot keep pace with evolving zero-day threats or complex codebases.

**KALPA** addresses the **AI Kavach** challenge by going beyond correlational symptom-matching. It introduces **Causal Cyber Reasoning**:
1. **Reconstructing Root Causes**: Reconstructing why a vulnerability arises (tracing input flow $\to$ control/data flow $\to$ exploit sink).
2. **Targeted Causal Interventions**: Synthesizing minimal patches that remove the true root cause while preserving functional behavior.
3. **Executable Security Contracts**: Compiling vulnerability knowledge into durable contracts (code assertions, regression test suites, and fuzzing oracles).
4. **Self-Adversarial Repair Loop**: Continuously attacking its own generated patches with automated fuzzing to prove fixes hold without human intervention.

---

## ⚡ Architecture Overview

```
                      +------------------------------------+
                      |   Target Intake & Code Slicing     |
                      +-----------------+------------------+
                                        |
                                        v
                      +------------------------------------+
                      | Static & Dynamic Analysis / Fuzz   |
                      |   (SARIF, Sanitizers, POV Inputs)  |
                      +-----------------+------------------+
                                        |
                                        v
                      +------------------------------------+
                      |    KALPA Causal Reasoning Engine   |
                      |   (LLM Brain & Causal Graph JSON)  |
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

## 📦 Key System Modules

| Module | Responsibility | Key File |
| :--- | :--- | :--- |
| **Static Analysis** | Intake SARIF reports, perform AST/regex scanning, slice code around sensitive sinks | [`kalpa/static_analysis/analyzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/analyzer.py) |
| **Dynamic Fuzzing** | Automated test harness generation, input payload mutation, stack trace & sanitizer log capture | [`kalpa/dynamic_analysis/fuzzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/fuzzer.py) |
| **Causal LLM Brain** | Builds causal graph JSON, pinpoints root causes, ranks interventions by security impact & safety | [`kalpa/causal_engine/reasoner.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/reasoner.py) |
| **Patch Synthesizer** | Generates minimal, clean unified code diffs respecting project code style & AST validity | [`kalpa/patching/synthesizer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/patching/synthesizer.py) |
| **Contract Compiler** | Translates root causes into code assertions, unit tests, and fuzzing oracles | [`kalpa/contract_compiler/compiler.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/compiler.py) |
| **Self-Adversarial Loop**| Autonomous controller coordinating intake $\to$ fuzz $\to$ patch $\to$ re-attack $\to$ accept/reject decisions | [`kalpa/orchestrator/controller.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/orchestrator/controller.py) |
| **Daemon File Watcher**| Tracks file `(st_mtime, st_size)` signatures to avoid redundant re-reads during background polling | [`kalpa/utils/file_watcher.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/utils/file_watcher.py) |

---

## 🚀 Quick Start & Usage

### Single-Command Execution

To execute KALPA on any target repository:

```bash
python run_kalpa.py --target targets/vulnerable_service --output-dir evidence_bundles
```

Or via shell wrapper:

```bash
chmod +x run_kalpa.sh
./run_kalpa.sh targets/vulnerable_service evidence_bundles
```

### Options & Flags

```text
usage: run_kalpa.py [-h] [--target TARGET] [--sarif SARIF] [--output-dir OUTPUT_DIR]
                    [--provider {auto,openai,anthropic,gemini,rule_based}] [--max-fuzz-time MAX_FUZZ_TIME]

Options:
  -t, --target           Target codebase directory path (default: targets/vulnerable_service)
  -s, --sarif            Optional path to SARIF static report file
  -o, --output-dir       Directory to export Evidence Bundles (default: evidence_bundles)
  --provider             LLM Engine mode ('auto', 'openai', 'anthropic', 'gemini', 'rule_based')
  --max-fuzz-time        Fuzzing budget per vulnerability in seconds (default: 30)
```

---

## 🔬 Benchmark Verification & Tests

Run the full framework unit and integration test suite:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 🛡️ Defense-Ready Evidence Bundles

Every fix processed by KALPA generates an auditable, defense-ready **Evidence Bundle** located in `evidence_bundles/<VULN_ID>/`:
- `evidence_bundle.json`: Complete machine-readable analysis & metrics.
- `causal_explanation.md`: Human-readable causal narrative and root cause analysis.
- `patch.diff`: Unified patch diff.
- `test_contract_*.py`: Executable security contract test.

---

## 📑 Core Guidelines & Architectural Constraints

- **SQLAlchemy Read Methods**: All ORM queries call `session.expunge_all()` before `session.close()` to prevent detached instance access errors across async/multi-scoped frameworks.
- **SQLite Datetime Normalization**: Datetimes are normalized to UTC-naive at the ingestion/parse layer to prevent offset-naive/offset-aware subtraction errors.
- **Daemon Signature Tracking**: Background file polling tracks `(st_mtime, st_size)` in `_file_seen_signature: Dict[str, tuple]` to eliminate duplicate event processing.
