# KALPA: Autonomous Causal Cyber Reasoning System (CRS)

[![PyPI Version](https://img.shields.io/badge/pypi-v2.0.1-10b981.svg)](https://pypi.org/project/kalpa-crs/)
[![Python Version](https://img.shields.io/badge/python-3.9+-38bdf8.svg)](https://www.python.org/)
[![Build Status](https://img.shields.io/badge/build-passing-10b981.svg)](#)
[![Docker Ready](https://img.shields.io/badge/docker-containerized-ea580c.svg)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **KALPA** is an enterprise-grade autonomous **Cyber Reasoning System (CRS)** engineered to discover zero-day vulnerabilities, reconstruct causal root causes, synthesize minimal code remediations, compile executable security contracts, and prove fix robustness through a self-adversarial repair harness without human intervention.

---

## Table of Contents
1. [System Overview](#system-overview)
2. [Causal Cyber Reasoning Paradigm](#causal-cyber-reasoning-paradigm)
3. [Architecture & Pipeline Flow](#architecture--pipeline-flow)
4. [Project Structure & Component Directory](#project-structure--component-directory)
5. [Technical Features & Capabilities](#technical-features--capabilities)
   - [Multi-Language Support](#multi-language-support)
   - [Air-Gapped Local LLM Provider Integration](#air-gapped-local-llm-provider-integration)
   - [Native AFL++/libFuzzer C Harness Generator](#native-afl-libfuzzer-c-harness-generator)
   - [CI/CD Security Contract Exporter](#cicd-security-contract-exporter)
   - [Interactive Defense Operations Web Dashboard](#interactive-defense-operations-web-dashboard)
6. [Strict Engineering Rules & Compliance](#strict-engineering-rules--compliance)
7. [Installation](#installation)
8. [Usage Manual & Command Reference](#usage-manual--command-reference)
   - [1. Command-Line Interface (CLI)](#1-command-line-interface-cli)
   - [2. Air-Gapped Local Model Execution](#2-air-gapped-local-model-execution)
   - [3. Interactive Web Operations Dashboard](#3-interactive-web-operations-dashboard)
   - [4. Docker Container Deployment](#4-docker-container-deployment)
   - [5. CI/CD Workflow Generation](#5-cicd-workflow-generation)
   - [6. Evaluation & Benchmark Runner](#6-evaluation--benchmark-runner)
9. [Configuration Reference](#configuration-reference)
10. [Auditable Evidence Bundle Format](#auditable-evidence-bundle-format)
11. [Verification & Testing](#verification--testing)
12. [License](#license)

---

## System Overview

Modern software ecosystems operating in mission-critical environments require continuous, automated vulnerability management. Traditional static application security testing (SAST) and dynamic testing (DAST) tools generate overwhelming false positive rates and rely on manual human triage. 

**KALPA** bridges this gap by unifying static code analysis, dynamic fuzzing, Large Language Model (LLM) causal reasoning, and self-adversarial validation into an autonomous engineering pipeline. Designed to run seamlessly in cloud infrastructure, local development environments, or air-gapped networks, KALPA autonomously transforms unverified code flaws into verified, regression-tested defense patches and executable security contracts.

---

## Causal Cyber Reasoning Paradigm

Most automated patching algorithms rely on superficial pattern matching—often wrapping failing calls in generic exception handlers or silencing error outputs. KALPA introduces **Causal Cyber Reasoning**:

1. **Root-Cause Graphing**: Traces input taint propagation through intermediate control and data flows directly to the root-cause sink.
2. **Causal Interventions**: Synthesizes minimal code diffs targeting the exact root cause while strictly preserving non-vulnerable system behavior.
3. **Executable Security Contracts**: Encodes vulnerability knowledge into durable security contracts (code assertions, pytest regression suites, and memory sanitization oracles).
4. **Self-Adversarial Loop**: Re-attacks patched binaries using dynamic fuzzing to empirically prove vulnerability elimination prior to deployment.

---

## Architecture & Pipeline Flow

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

### Detailed Pipeline Stage Breakdown:

* **Stage 1: Target Intake & Static Slicing**: Ingests source repositories, parses SARIF static analysis reports (Bandit/Semgrep), and extracts localized Abstract Syntax Tree (AST) code slices around candidate vulnerabilities.
* **Stage 2: Dynamic Fuzzing & POV Confirmation**: Executes mutation-based dynamic payloads against the active service to verify exploitability and capture crash trace logs.
* **Stage 3: Causal LLM Reasoning**: Invokes the Causal LLM Brain to reconstruct the taint propagation graph from source intake to sink execution, identifying the exact root cause.
* **Stage 4: Patch & Security Contract Compilation**: Synthesizes minimal, syntactically valid code diffs and compiles executable security contracts (assertions and targeted pytest suites).
* **Stage 5: Self-Adversarial Repair Harness**: Applies synthesized patches, re-runs original regression test suites, and re-fuzzes the patched binary to verify zero-regression.
* **Stage 6: Evidence Bundle Export**: Packages auditable evidence artifacts containing machine-readable JSON reports, causal graph visualizers, unified diffs, and contract test suites.

---

## Project Structure & Component Directory

| Module / Path | Description | Authoritative Source File |
| :--- | :--- | :--- |
| `kalpa.static_analysis` | SARIF 2.1.0 report ingestion, AST Python code slicing, C/C++ regex scanner | [`analyzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/analyzer.py) |
| `kalpa.static_analysis.sarif_parser` | Standard SARIF report parser for Bandit and Semgrep findings | [`sarif_parser.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/sarif_parser.py) |
| `kalpa.dynamic_analysis` | Dynamic fuzzer, payload mutation engine, crash trace logger, POV confirmation generator | [`fuzzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/fuzzer.py) |
| `kalpa.dynamic_analysis.c_harness_generator` | Standalone C `LLVMFuzzerTestOneInput` AFL++/libFuzzer harness generator | [`c_harness_generator.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/c_harness_generator.py) |
| `kalpa.dynamic_analysis.pov_generator` | Confirmed Proof-of-Vulnerability payload serializer | [`pov_generator.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/pov_generator.py) |
| `kalpa.causal_engine` | Causal LLM reasoning brain, structured prompt construction, causal graph JSON generator | [`reasoner.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/reasoner.py) |
| `kalpa.causal_engine.local_provider` | Native air-gapped provider for local Ollama (`/api/chat`) and vLLM (`/v1/chat/completions`) | [`local_provider.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/local_provider.py) |
| `kalpa.patching` | Minimal code diff synthesizer for Python & native C/C++ targets (`strncpy`/`snprintf`) | [`synthesizer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/patching/synthesizer.py) |
| `kalpa.contract_compiler` | Compiles security contracts into pytest suites, code assertions, and fuzzing oracles | [`compiler.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/compiler.py) |
| `kalpa.contract_compiler.cicd_exporter` | Generates GitHub Actions workflows (`.github/workflows/kalpa_contracts.yml`) | [`cicd_exporter.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/cicd_exporter.py) |
| `kalpa.orchestrator` | Central autonomous controller orchestrating intake -> fuzz -> patch -> re-attack -> evidence | [`controller.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/orchestrator/controller.py) |
| `kalpa.dashboard` | FastAPI server backing the interactive glassmorphism Web Operations Dashboard | [`app.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dashboard/app.py) |
| `kalpa.utils.file_watcher` | Signature-tracked daemon file watcher maintaining `(st_mtime, st_size)` cache | [`file_watcher.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/utils/file_watcher.py) |

---

## Technical Features & Capabilities

### Multi-Language Support
* **Python Microservices**: Detects and remediates SQL Injection, Path Traversal, Command Injection, and authentication flaws in Flask, FastAPI, and SQLAlchemy applications.
* **Native C/C++ Services**: Identifies and remediates Buffer Overflows (`strcpy` -> `strncpy`, `sprintf` -> `snprintf`), format string vulnerabilities, and unsafe `system()` calls under AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan).

### Air-Gapped Local LLM Provider Integration
Supports classified, isolated network environments via direct REST client integration with local inference engines:
* **Ollama**: Connects directly to local Ollama endpoints (`http://localhost:11434/api/chat`) supporting models such as `deepseek-coder`, `llama3`, and `qwen2.5-coder`.
* **vLLM**: Connects to OpenAI-compatible vLLM endpoints (`http://localhost:8000/v1/chat/completions`) with strict JSON schema validation.

### Native AFL++/libFuzzer C Harness Generator
Auto-synthesizes standalone C entrypoint functions (`LLVMFuzzerTestOneInput`) targeting specific C functions:
* Allocates memory-bounded fuzzing buffers under AddressSanitizer monitoring.
* Integrates directly into dynamic build pipelines to catch memory safety violations.

### CI/CD Security Contract Exporter
Generates non-regression continuous integration workflows:
* Generates `.github/workflows/kalpa_contracts.yml` automatically upon target evaluation.
* Ensures every synthesized security contract is re-tested on future git commits and pull requests.

### Interactive Defense Operations Web Dashboard
FastAPI server serving an interactive web interface:
* **Warm Off-White Glassmorphism UI**: Uses dark espresso typography (`#2b211b`) and terracotta orange accents (`#ea580c`).
* **SVG Causal Graph Visualizer**: Dynamic vector visualizer rendering multi-node causal graphs with automatic multiline text wrapping and drop shadow filters.
* **Side-by-Side Modal Inspector**: Inspect unified diffs, pytest security contracts, POV payloads, and raw JSON bundles.

---

## Strict Engineering Rules & Compliance

KALPA enforces strict internal implementation invariants across all modules:

1. **SQLAlchemy ORM Read Safety**: All ORM read methods execute `session.expunge_all()` prior to `session.close()`. Database relationships use `lazy="subquery"` or `lazy="joined"` (never `lazy="select"`) to ensure returned ORM objects remain fully accessible outside active session scopes.
2. **SQLite UTC-Naive Datetime Normalization**: Normalizes datetimes to UTC-naive at input ingestion via `normalize_to_utc_naive()` (stripping `tzinfo` after converting to UTC) to eliminate type errors during date comparisons.
3. **File-Polling Signature Cache**: Daemon file watcher loops maintain a `(st_mtime, st_size)` signature dictionary (`_file_seen_signature`) per file path to prevent redundant file reads, log noise, and memory overhead.

---

## Installation

### Option 1: Install via PyPI (Recommended)

```bash
pip install kalpa-crs
```

### Option 2: Install from Source

```bash
# Clone repository
git clone https://github.com/hazlived/kalpa.git
cd kalpa

# Install in editable mode with dependencies
pip install -e .
```

---

## Usage Manual & Command Reference

### 1. Command-Line Interface (CLI)

Run KALPA autonomously against any codebase:

```bash
python run_kalpa.py --target targets/vulnerable_service --output-dir evidence_bundles
```

---

### 2. Air-Gapped Local Model Execution

Execute KALPA using a local Ollama model:

```bash
python run_kalpa.py --target targets/vulnerable_service --provider ollama --ollama-host http://localhost:11434 --model deepseek-coder
```

---

### 3. Interactive Web Operations Dashboard

Launch the FastAPI web dashboard server:

```bash
python run_kalpa.py --dashboard
```

Access the interface at **`http://127.0.0.1:8000`**.

---

### 4. Docker Container Deployment

Run KALPA in containerized environments:

```bash
# Build Docker image
docker build -t kalpa-crs .

# Run container
docker run --rm -v $(pwd)/evidence_bundles:/app/evidence_bundles kalpa-crs --target targets/vulnerable_service
```

Or via Docker Compose:

```bash
docker-compose up --build
```

---

### 5. CI/CD Workflow Generation

Export GitHub Actions continuous integration workflows:

```bash
python run_kalpa.py --target targets/vulnerable_service --export-cicd
```

Generates `.github/workflows/kalpa_contracts.yml`.

---

### 6. Evaluation & Benchmark Runner

Execute benchmark evaluation across target services:

```bash
python eval_kalpa.py --targets-dir targets --output eval_report.json
```

Outputs `eval_report.json` detailing Patch Success Rate (PSR), Mean Time to Repair (MTTR), and system resource usage.

---

## Configuration Reference

| Parameter / Variable | CLI Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `LLM_PROVIDER` | `--provider` | Reasoning provider mode (`auto`, `openai`, `ollama`, `vllm`, `rule_based`) | `auto` |
| `LLM_MODEL` | `--model` | Model name for remote or local provider | `gpt-4o` / `deepseek-coder` |
| `OLLAMA_HOST` | `--ollama-host` | Endpoint URL for local Ollama or vLLM server | `http://localhost:11434` |
| `MAX_FUZZ_TIME` | `--max-fuzz-seconds` | Maximum fuzzing budget per target vulnerability (seconds) | `30` |
| `OUTPUT_DIR` | `--output-dir` | Target directory for generated evidence bundles | `evidence_bundles` |

---

## Auditable Evidence Bundle Format

Every fix processed by KALPA exports an evidence bundle to `evidence_bundles/<VULN_ID>/`:

* `evidence_bundle.json`: Machine-readable report containing vulnerability details, causal node graph, patch state, and performance metrics.
* `causal_explanation.md`: Human-readable technical markdown report detailing the vulnerability root cause and taint propagation path.
* `patch.diff`: Unified code diff ready for application via `git apply`.
* `test_contract_*.py`: Executable pytest security contract verifying vulnerability non-regression.

---

## Verification & Testing

Execute the framework unit test suite (100% pass rate):

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for full details.
