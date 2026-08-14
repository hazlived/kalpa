# KALPA: Autonomous Causal Cyber Reasoning System — Technical Audit & Architecture Report

[![KALPA CRS](https://img.shields.io/badge/KALPA_CRS-Technical_Report-blue.svg)](#)
[![Version: 2.0.0](https://img.shields.io/badge/version-v2.0.0_Production-emerald.svg)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 🏛️ Executive Summary

**KALPA** is an autonomous Cyber Reasoning System (CRS) engineered to discover vulnerabilities, reconstruct causal root causes, synthesize safe remediations, compile durable security contracts, and prove fix robustness through a self-adversarial validation loop without human intervention.

Designed for high-stakes mission-critical software environments, KALPA implements **Causal Cyber Reasoning**: replacing superficial symptom patching with root-cause elimination.

---

## 🎯 Core Technical Achievements

### 1. Functional Capabilities
- ✅ **Autonomous Vulnerability Discovery**: Ingests target codebases and discovers exploitable vulnerabilities across Python web microservices (SQL Injection, Path Traversal, Command Injection) and native C/C++ services (Buffer Overflows, unsafe string formatting, `system()` calls).
- ✅ **Syntactically Correct Patches**: Synthesizes minimal code diffs that preserve project coding style, AST validity, and existing functionality.
- ✅ **POV Elimination**: Confirms reproducible Proof-of-Vulnerability (POV) payloads and verifies their elimination post-patching.

### 2. Security Capabilities
- ✅ **Causal Explanations**: Produces structured Causal Graph JSONs and narratives detailing input taint propagation $\to$ control/data flow $\to$ root cause sink.
- ✅ **Executable Security Contracts**: Compiles durable security knowledge into code-level assertions, targeted pytest suites (`test_contract_*.py`), and fuzzing oracles encoding safe invariant behavior.

### 3. Operational Capabilities
- ✅ **Single-Command & Air-Gapped Deployment**: Deploys via single command (`python run_kalpa.py`), air-gapped Docker container (`Dockerfile`), or local LLM inference (`Ollama` / `vLLM`).
- ✅ **Measurable Metrics**: Evaluated via [`eval_kalpa.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/eval_kalpa.py) recording Patch Success Rate (PSR), Mean Time to Repair (MTTR), and CPU/RAM/Token utilization.

---

## ⚡ System Architecture & Pipeline

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

## 📊 Benchmark & Evaluation Results (`eval_report.json`)

| Target Service | Language | Found | Fixed | Patch Success Rate (PSR) | Mean Time to Repair (MTTR) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `vulnerable_service` | Python (Flask/SQLAlchemy) | 2 | 2 | **100.0%** | **2.51s** |
| `vulnerable_cpp_service` | C/C++ (GCC/ASan) | 4 | 2 | **50.0%** | **2.26s** |
| **TOTAL BENCHMARK** | **Multi-Language** | **6** | **4** | **66.7%** | **2.42s** |

---

## 🛡️ Auditable Evidence Bundle Specification

Every fix generates an auditable Evidence Bundle in `evidence_bundles/<VULN_ID>/`:
- `evidence_bundle.json`: Complete machine-readable findings, causal explanation, and metrics.
- `causal_explanation.md`: Causal narrative detailing root cause and taint path.
- `patch.diff`: Unified code diff.
- `test_contract_*.py`: Executable pytest security contract.

---

## 🚀 Deployment Modes

### 1. Interactive Operations Web Dashboard
```bash
python run_kalpa.py --dashboard
```
Access the web dashboard at **`http://127.0.0.1:8000`**.

### 2. Air-Gapped Local LLM Execution (Ollama / vLLM)
```bash
python run_kalpa.py --target targets/vulnerable_service --provider ollama --ollama-host http://localhost:11434 --model deepseek-coder
```

### 3. Docker Container Deployment
```bash
docker build -t kalpa-crs .
docker run --rm -v $(pwd)/evidence_bundles:/app/evidence_bundles kalpa-crs --target targets/vulnerable_service
```

### 4. CI/CD Security Contract Workflow Exporter
```bash
python run_kalpa.py --target targets/vulnerable_service --export-cicd
```
Exports ready-to-commit GitHub Actions continuous integration workflow `.github/workflows/kalpa_contracts.yml`.
