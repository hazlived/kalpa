# KALPA: Autonomous Causal Cyber Reasoning System (CRS)

[![PyPI version](https://img.shields.io/pypi/v/kalpa-crs.svg?color=10b981)](https://pypi.org/project/kalpa-crs/)
[![Python versions](https://img.shields.io/pypi/pyversions/kalpa-crs.svg?color=38bdf8)](https://pypi.org/project/kalpa-crs/)
[![Build Status](https://img.shields.io/badge/build-passing-10b981.svg)](#)
[![Docker Ready](https://img.shields.io/badge/docker-containerized-ea580c.svg)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **KALPA** is an enterprise-grade autonomous **Cyber Reasoning System (CRS)** engineered to discover zero-day vulnerabilities, reconstruct causal root causes, synthesize minimal code remediations, compile executable security contracts, and prove fix robustness through a self-adversarial repair harness without human intervention.

---

## 📑 Table of Contents
1. [Executive Overview](#-executive-overview)
2. [Causal Cyber Reasoning Paradigm](#-causal-cyber-reasoning-paradigm)
3. [System Architecture & Engineering Loop](#-system-architecture--engineering-loop)
4. [Core Modules & Component Directory](#-core-modules--component-directory)
5. [Feature Matrix & Technical Capabilities](#-feature-matrix--technical-capabilities)
6. [Installation](#-installation)
7. [Comprehensive Usage Guide](#-comprehensive-usage-guide)
   - [1. Command Line Interface (CLI)](#1-command-line-interface-cli)
   - [2. Air-Gapped Local LLM Execution (Ollama / vLLM)](#2-air-gapped-local-llm-execution-ollama--vllm)
   - [3. Interactive Defense Operations Web Dashboard](#3-interactive-defense-operations-web-dashboard)
   - [4. Containerized Docker Deployment](#4-containerized-docker-deployment)
   - [5. CI/CD Security Contract Exporter](#5-cicd-security-contract-exporter)
   - [6. Benchmark & Evaluation Suite](#6-benchmark--evaluation-suite)
8. [Configuration Reference](#-configuration-reference)
9. [Auditable Evidence Bundle Specification](#-auditable-evidence-bundle-specification)
10. [Verification & Testing](#-verification--testing)
11. [License](#-license)

---

## 🏛️ Executive Overview

Modern software ecosystems operating in mission-critical environments require continuous, automated vulnerability management. Traditional static application security testing (SAST) and dynamic testing (DAST) tools generate overwhelming false positive rates and rely on manual human triage. 

**KALPA** bridges this gap by unifying static code analysis, dynamic fuzzing, Large Language Model (LLM) causal reasoning, and self-adversarial validation into an autonomous engineering pipeline. Designed to run seamlessly in cloud infrastructure, local development environments, or air-gapped networks, KALPA autonomously transforms unverified code flaws into verified, regression-tested defense patches and executable security contracts.

---

## 🎯 Causal Cyber Reasoning Paradigm

Most automated patching algorithms rely on superficial pattern matching—often wrapping failing calls in generic exception handlers or silencing error outputs. KALPA introduces **Causal Cyber Reasoning**:

1. **Root-Cause Graphing**: Traces input taint propagation through intermediate control and data flows directly to the root-cause sink.
2. **Causal Interventions**: Synthesizes minimal code diffs targeting the exact root cause while strictly preserving non-vulnerable system behavior.
3. **Executable Security Contracts**: Encodes vulnerability knowledge into durable security contracts (code assertions, pytest regression suites, and memory sanitization oracles).
4. **Self-Adversarial Loop**: Re-attacks patched binaries using dynamic fuzzing to empirically prove vulnerability elimination prior to deployment.

---

## ⚡ System Architecture & Engineering Loop

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

## 📦 Core Modules & Component Directory

| Package / File | Description | Link |
| :--- | :--- | :--- |
| `kalpa.static_analysis` | SARIF 2.1.0 ingestion, AST Python code slicing, C/C++ regex vulnerability discovery | [`analyzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/analyzer.py) |
| `kalpa.dynamic_analysis` | Dynamic fuzzer, payload mutation engine, crash trace parser, POV confirmation generator | [`fuzzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/fuzzer.py) |
| `kalpa.dynamic_analysis.c_harness_generator` | Standalone C `LLVMFuzzerTestOneInput` AFL++/libFuzzer harness generator | [`c_harness_generator.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/c_harness_generator.py) |
| `kalpa.causal_engine` | Causal LLM brain, structured prompt construction, causal graph JSON generator | [`reasoner.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/reasoner.py) |
| `kalpa.causal_engine.local_provider` | Native air-gapped provider for local Ollama (`/api/chat`) and vLLM (`/v1/chat/completions`) | [`local_provider.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/local_provider.py) |
| `kalpa.patching` | Minimal code diff synthesizer for Python & native C/C++ targets (`strncpy`/`snprintf`) | [`synthesizer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/patching/synthesizer.py) |
| `kalpa.contract_compiler` | Compiles security contracts into pytest suites, code assertions, and fuzzing oracles | [`compiler.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/compiler.py) |
| `kalpa.contract_compiler.cicd_exporter` | Generates GitHub Actions workflows (`.github/workflows/kalpa_contracts.yml`) | [`cicd_exporter.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/cicd_exporter.py) |
| `kalpa.orchestrator` | Central autonomous controller orchestrating intake $\to$ fuzz $\to$ patch $\to$ re-attack $\to$ evidence | [`controller.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/orchestrator/controller.py) |
| `kalpa.dashboard` | FastAPI server backing the interactive glassmorphism Web Operations Dashboard | [`app.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dashboard/app.py) |
| `kalpa.utils.file_watcher` | Signature-tracked daemon file watcher maintaining `(st_mtime, st_size)` cache | [`file_watcher.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/utils/file_watcher.py) |

---

## 🛠️ Feature Matrix & Technical Capabilities

- 🐍 **Python Microservice Remediation**: Detects and remediates SQL Injection, Path Traversal, Command Injection, and authentication bypasses in Flask, FastAPI, and SQLAlchemy microservices.
- ⚙️ **Native C/C++ Memory Safety**: Identifies and remediates Buffer Overflows (`strcpy` $\to$ `strncpy`, `sprintf` $\to$ `snprintf`), format string bugs, and unsafe `system()` invocations under AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan).
- 🔒 **100% Air-Gapped Local LLM Support**: Direct integration with locally hosted Ollama or vLLM instances (`DeepSeek-Coder`, `Llama-3`) with strict JSON schema validation.
- 🌐 **Interactive Operations Web Dashboard**: FastAPI backend paired with a warm off-white glassmorphism UI, interactive SVG Causal Graph visualizer, real-time log streaming, and side-by-side patch diff inspector.
- ⚙️ **Continuous Integration Workflow Exporter**: Automated generation of ready-to-commit GitHub Actions workflows (`.github/workflows/kalpa_contracts.yml`).
- 📜 **Strict Engineering Compliance**:
  - **SQLAlchemy ORM Read Safety**: All ORM read methods execute `session.expunge_all()` prior to `session.close()` with `lazy="subquery"` relationship loading.
  - **SQLite UTC-Naive Datetime Normalization**: Strips timezone offsets at parse layer via `normalize_to_utc_naive()` to eliminate runtime offset comparison errors.
  - **File-Polling Signature Cache**: Daemon file watcher tracks `(st_mtime, st_size)` in `_file_seen_signature` to prevent duplicate re-read overhead.

---

## 🚀 Installation

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

## 📖 Comprehensive Usage Guide

### 1. Command Line Interface (CLI)

Run KALPA autonomously against any codebase:

```bash
python run_kalpa.py --target targets/vulnerable_service --output-dir evidence_bundles
```

---

### 2. Air-Gapped Local LLM Execution (Ollama / vLLM)

Execute KALPA in isolated networks using a locally hosted LLM model:

```bash
python run_kalpa.py --target targets/vulnerable_service --provider ollama --ollama-host http://localhost:11434 --model deepseek-coder
```

---

### 3. Interactive Defense Operations Web Dashboard

Launch the web dashboard server:

```bash
python run_kalpa.py --dashboard
```

Navigate to **`http://127.0.0.1:8000`** to access the operations dashboard featuring real-time status tracking, interactive SVG Causal Graph visualization, target microservice execution triggers, and code diff modal inspection.

---

### 4. Containerized Docker Deployment

Run KALPA within a containerized environment:

```bash
# Build Docker image
docker build -t kalpa-crs .

# Run container
docker run --rm -v $(pwd)/evidence_bundles:/app/evidence_bundles kalpa-crs --target targets/vulnerable_service
```

Or using Docker Compose:

```bash
docker-compose up --build
```

---

### 5. CI/CD Security Contract Exporter

Export GitHub Actions workflows to enforce non-regression on every git push:

```bash
python run_kalpa.py --target targets/vulnerable_service --export-cicd
```

Generates `.github/workflows/kalpa_contracts.yml`.

---

### 6. Benchmark & Evaluation Suite

Execute the benchmark evaluator across all target services:

```bash
python eval_kalpa.py --targets-dir targets --output eval_report.json
```

Outputs machine-readable `eval_report.json` detailing Patch Success Rate (PSR), Mean Time to Repair (MTTR), and system resource usage.

---

## ⚙️ Configuration Reference

| Parameter / Variable | CLI Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `LLM_PROVIDER` | `--provider` | Reasoning provider mode (`auto`, `openai`, `ollama`, `vllm`, `rule_based`) | `auto` |
| `LLM_MODEL` | `--model` | Model name for remote or local provider | `gpt-4o` / `deepseek-coder` |
| `OLLAMA_HOST` | `--ollama-host` | URL endpoint for local Ollama or vLLM server | `http://localhost:11434` |
| `MAX_FUZZ_TIME` | `--max-fuzz-seconds` | Maximum fuzzing budget per target vulnerability (seconds) | `30` |
| `OUTPUT_DIR` | `--output-dir` | Target directory for generated evidence bundles | `evidence_bundles` |

---

## 🛡️ Auditable Evidence Bundle Specification

For every processed vulnerability, KALPA outputs an auditable Evidence Bundle to `evidence_bundles/<VULN_ID>/`:

- `evidence_bundle.json`: Structured machine-readable findings, causal graph, patch outcome, and execution metrics.
- `causal_explanation.md`: Human-readable technical markdown report detailing the vulnerability root cause and taint propagation path.
- `patch.diff`: Standard unified diff ready for application via `git apply`.
- `test_contract_*.py`: Executable pytest contract verifying vulnerability non-regression.

---

## 🔬 Verification & Testing

Execute the full framework test suite:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
