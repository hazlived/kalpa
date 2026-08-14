# KALPA: Causal Cyber Reasoning System for AI Kavach

[![AI Kavach CRS](https://img.shields.io/badge/AI_Kavach-Grand_Finale_Deliverable-blue.svg)](FINAL_DELIVERABLES.md)
[![Version 2.0.0](https://img.shields.io/badge/version-v2.0.0_Final-10b981.svg)](CHANGELOG.md)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-38bdf8.svg)](https://www.python.org/)
[![Docker Ready](https://img.shields.io/badge/docker-containerized-ea580c.svg)](Dockerfile)
[![License: Defense Grade](https://img.shields.io/badge/license-Defense_Ready-be123c.svg)](LICENSE)

> **KALPA** is an autonomous **Causal Cyber Reasoning System (CRS)** designed to discover vulnerabilities, reconstruct causal root causes, synthesize minimal code patches, compile durable security contracts, and prove fix robustness through a self-adversarial repair loop without human intervention. Built for mission-critical defense software in the simulated Indian Armed Forces operational environments (**AI Kavach**).

---

## 📑 Table of Contents
1. [Executive Overview & Motivation](#-executive-overview--motivation)
2. [Causal Cyber Reasoning vs. Symptom Patching](#-causal-cyber-reasoning-vs-symptom-patching)
3. [System Architecture Overview](#-system-architecture-overview)
4. [Key System Components & File Directory](#-key-system-components--file-directory)
5. [Feature Matrix & Core Capabilities](#-feature-matrix--core-capabilities)
6. [Installation & Setup](#-installation--setup)
7. [Comprehensive Usage Manual](#-comprehensive-usage-manual)
   - [1. Single-Command CLI Execution](#1-single-command-cli-execution)
   - [2. Air-Gapped Local LLM Execution (Ollama / vLLM)](#2-air-gapped-local-llm-execution-ollama--vllm)
   - [3. Interactive Defense Operations Web Dashboard](#3-interactive-defense-operations-web-dashboard)
   - [4. Docker Container Deployment](#4-docker-container-deployment)
   - [5. AI Kavach Evaluation Suite](#5-ai-kavach-evaluation-suite)
   - [6. CI/CD Security Contract Exporter](#6-cicd-security-contract-exporter)
8. [Configuration & Environment Variables](#-configuration--environment-variables)
9. [Auditable Evidence Bundle Specification](#-auditable-evidence-bundle-specification)
10. [Benchmark Results & Performance Indicators](#-benchmark-results--performance-indicators)
11. [Testing & Verification](#-testing--verification)
12. [Project Documentation & Audit Dossier](#-project-documentation--audit-dossier)

---

## 🏛️ Executive Overview & Motivation

Defense and national security software operates under extreme reliability and security constraints. Vulnerabilities in military microservices or embedded software can translate directly into mission failure, operational compromise, or loss of life. Traditional vulnerability management workflows—manual code triage, human-written patches, slow regression testing cycles, and correlational static scanners—cannot scale with complex, evolving codebases.

**AI Kavach** challenges participants to build a Cyber Reasoning System (CRS) that lace Large Language Models (LLMs) with fuzzers, static/dynamic analyzers, and a regression harness to autonomously discover vulnerabilities, patch them, and prove fixes hold without human intervention.

---

## 🎯 Causal Cyber Reasoning vs. Symptom Patching

Most automated patching tools perform superficial correlational fixes (e.g., masking error return values or wrapping code in try/catch blocks). **KALPA** introduces **Causal Cyber Reasoning**:

1. **Reconstructing Root Causes**: Traces input taint propagation through intermediate control and data flows directly to the exploit sink.
2. **Targeted Causal Interventions**: Synthesizes minimal code diffs that remove the true root cause while preserving 100% of legitimate system functionality.
3. **Executable Security Contracts**: Compiles vulnerability knowledge into durable security contracts (assertions, pytest regression suites, and fuzzing oracles).
4. **Self-Adversarial Repair Loop**: Attempts to re-exploit patched binaries using automated fuzzing and regression tests to prove fix robustness.

---

## ⚡ System Architecture Overview

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

## 📦 Key System Components & File Directory

| Module | Responsibility | Key Implementation File |
| :--- | :--- | :--- |
| **Static Analyzer** | Ingest SARIF reports, AST Python analysis, C/C++ regex scan, code line-slicing | [`kalpa/static_analysis/analyzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/analyzer.py) |
| **SARIF Parser** | Standard SARIF 2.1.0 and Bandit/Semgrep report intake | [`kalpa/static_analysis/sarif_parser.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/sarif_parser.py) |
| **Dynamic Fuzzer** | Payload mutation engine, dynamic test runner, crash & sanitizer log tracer | [`kalpa/dynamic_analysis/fuzzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/fuzzer.py) |
| **C Harness Generator** | AFL++/libFuzzer C harness auto-generator (`LLVMFuzzerTestOneInput`) | [`kalpa/dynamic_analysis/c_harness_generator.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/c_harness_generator.py) |
| **POV Generator** | Confirmed Proof-of-Vulnerability payload generation | [`kalpa/dynamic_analysis/pov_generator.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/pov_generator.py) |
| **Causal LLM Brain** | Causal narrative builder, root-cause identifier, intervention strategy ranker | [`kalpa/causal_engine/reasoner.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/reasoner.py) |
| **Local LLM Provider** | Air-gapped Ollama (`/api/chat`) and vLLM (`/v1/chat/completions`) provider | [`kalpa/causal_engine/local_provider.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/local_provider.py) |
| **Patch Synthesizer** | Minimal, syntactically correct code diff synthesizer (Python & C/C++ `strncpy`/`snprintf`) | [`kalpa/patching/synthesizer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/patching/synthesizer.py) |
| **Contract Compiler** | Translates fixes into code assertions, pytest contracts, and fuzzing oracles | [`kalpa/contract_compiler/compiler.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/compiler.py) |
| **CI/CD Exporter** | Generates GitHub Actions non-regression workflows (`.github/workflows/kalpa_contracts.yml`) | [`kalpa/contract_compiler/cicd_exporter.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/cicd_exporter.py) |
| **Orchestrator Loop** | Central controller managing intake $\to$ fuzz $\to$ patch $\to$ re-attack $\to$ accept/reject decision | [`kalpa/orchestrator/controller.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/orchestrator/controller.py) |
| **Web Dashboard API** | FastAPI backend serving status, CRS runner, and evidence bundle endpoints | [`kalpa/dashboard/app.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dashboard/app.py) |
| **Daemon File Watcher**| Polls files tracking `(st_mtime, st_size)` signatures to eliminate redundant re-reads | [`kalpa/utils/file_watcher.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/utils/file_watcher.py) |

---

## 🛠️ Feature Matrix & Core Capabilities

- 🐍 **Python Microservice Support**: Detects and patches SQL Injection, Path Traversal, Command Injection, and Auth flaws in Flask, FastAPI, and SQLAlchemy microservices.
- ⚙️ **Native C/C++ Service Support**: Detects and remediates Buffer Overflows (`strcpy` $\to$ `strncpy`, `sprintf` $\to$ `snprintf`), format string issues, and unsafe `system()` calls under AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan).
- 🔒 **100% Air-Gapped Local LLM Inference**: Direct integration with local Ollama or vLLM inference servers (`DeepSeek-Coder`, `Llama-3`) with strict JSON schema validation.
- 🌐 **Interactive Defense Operations Web Dashboard**: FastAPI backend with a warm off-white terracotta UI, SVG Causal Graph visualizer, real-time telemetry stream, and code diff modal inspector.
- ⚙️ **CI/CD Security Contract Exporter**: Automatically outputs GitHub Actions workflows (`.github/workflows/kalpa_contracts.yml`) to enforce non-regression on every git commit.
- 📜 **Strict Compliance Rules**:
  - **SQLAlchemy ORM Read Methods**: All queries call `session.expunge_all()` before `session.close()` with `lazy="subquery"` relationships.
  - **SQLite UTC-Naive Datetime Normalization**: Normalizes datetimes to UTC-naive at input parse layer via `normalize_to_utc_naive()` stripping `tzinfo`.
  - **File-Polling Signature Cache**: Daemon file watcher tracks `(st_mtime, st_size)` in `_file_seen_signature` to prevent duplicate re-read overhead.

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.9 or higher
- GCC / Clang (for native C/C++ targets)
- Docker & Docker Compose (optional for containerized run)

### Setup Steps

```bash
# 1. Clone repository
git clone https://github.com/YOUR_USERNAME/kalpa.git
cd kalpa

# 2. Install dependencies
pip install -r requirements.txt
```

---

## 📖 Comprehensive Usage Manual

### 1. Single-Command CLI Execution
Run KALPA autonomously against any target codebase (Python microservice or C/C++ service):

```bash
python run_kalpa.py --target targets/vulnerable_service --output-dir evidence_bundles
```

---

### 2. Air-Gapped Local LLM Execution (Ollama / vLLM)
To execute KALPA in classified defense networks using a locally hosted LLM without internet connectivity:

```bash
python run_kalpa.py --target targets/vulnerable_service --provider ollama --ollama-host http://localhost:11434 --model deepseek-coder
```

---

### 3. Interactive Defense Operations Web Dashboard
Launch the FastAPI web dashboard server:

```bash
python run_kalpa.py --dashboard
```

Open your browser at **`http://127.0.0.1:8000`** to access the warm off-white terracotta dashboard featuring interactive SVG Causal Graph rendering, real-time log streaming, and side-by-side patch diff inspection.

---

### 4. Docker Container Deployment
Run KALPA inside an air-gapped Docker container:

```bash
# Build container image
docker build -t kalpa-crs .

# Run autonomous loop
docker run --rm -v $(pwd)/evidence_bundles:/app/evidence_bundles kalpa-crs --target targets/vulnerable_service
```

Or using Docker Compose:

```bash
docker-compose up --build
```

---

### 5. AI Kavach Evaluation Suite
Benchmark KALPA across all target codebases to compute AI Kavach performance metrics:

```bash
python eval_kalpa.py --targets-dir targets --output eval_report.json
```

Outputs machine-readable `eval_report.json` and human-readable `eval_report.md`.

---

### 6. CI/CD Security Contract Exporter
Export ready-to-commit GitHub Actions workflows:

```bash
python run_kalpa.py --target targets/vulnerable_service --export-cicd
```

Creates `.github/workflows/kalpa_contracts.yml` to automatically verify security contracts on git push.

---

## ⚙️ Configuration & Environment Variables

| Variable | Description | Default Value |
| :--- | :--- | :--- |
| `LLM_PROVIDER` | Reasoning provider mode (`auto`, `openai`, `ollama`, `vllm`, `rule_based`) | `auto` |
| `LLM_MODEL` | Remote LLM model name | `gpt-4o` |
| `LLM_API_KEY` | Remote API Key (OpenAI / Anthropic) | `None` |
| `OLLAMA_HOST` | Local Ollama / vLLM endpoint URL | `http://localhost:11434` |
| `LOCAL_MODEL` | Local LLM model name | `deepseek-coder` |
| `MAX_FUZZ_TIME` | Maximum fuzzing budget per vulnerability (seconds) | `30` |

---

## 🛡️ Auditable Evidence Bundle Specification

Every fix processed by KALPA exports an auditable Evidence Bundle to `evidence_bundles/<VULN_ID>/`:

- `evidence_bundle.json`: Complete machine-readable findings, causal explanation, and metrics.
- `causal_explanation.md`: Causal narrative detailing root cause and taint path.
- `patch.diff`: Unified code diff.
- `test_contract_*.py`: Executable pytest security contract.

---

## 📊 Benchmark Results & Performance Indicators

Evaluated using `eval_kalpa.py` across benchmark targets:

| Target Service | Language | Found | Fixed | Patch Success Rate (PSR) | MTTR (s) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `vulnerable_service` | Python (Flask/SQLAlchemy) | 2 | 2 | **100.0%** | **2.51s** |
| `vulnerable_cpp_service` | C/C++ (GCC/ASan) | 4 | 2 | **50.0%** | **2.26s** |
| **TOTAL BENCHMARK** | **Multi-Language** | **6** | **4** | **66.7%** | **2.42s** |

---

## 🔬 Testing & Verification

Run the full framework unit and integration test suite (100% pass rate):

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📑 Project Documentation & Audit Dossier

- 📄 [**AI Kavach Grand Finale Technical Deliverables & Audit Dossier**](FINAL_DELIVERABLES.md)
- 📜 [**Changelog & Release Notes**](CHANGELOG.md)
- ⚖️ [**License & Terms**](LICENSE)
