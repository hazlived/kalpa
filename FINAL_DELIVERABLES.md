# KALPA: AI Kavach Grand Finale Technical Deliverables & Audit Dossier

[![AI Kavach CRS](https://img.shields.io/badge/AI_Kavach-Grand_Finale_Deliverable-blue.svg)](#)
[![Version: 2.0.0](https://img.shields.io/badge/version-v2.0.0_Final-emerald.svg)](#)
[![License: Defense Ready](https://img.shields.io/badge/license-Defense_Ready-red.svg)](#)

---

## 🏛️ Executive Summary

**KALPA** is an autonomous Cyber Reasoning System (CRS) engineered to discover vulnerabilities, reconstruct causal root causes, synthesize safe remediations, compile durable security contracts, and prove fix robustness through a self-adversarial validation loop without human intervention.

Designed specifically for **AI Kavach**, KALPA addresses high-stakes software environments in the Indian Armed Forces by implementing **Causal Cyber Reasoning**: replacing superficial symptom patching with root-cause elimination.

---

## 🎯 Achievement of Core Objectives & Success Criteria

### 1. Functional Objectives
- ✅ **Autonomous Vulnerability Discovery**: Successfully ingests target codebases and discovers exploitable vulnerabilities across Python web microservices (SQL Injection, Path Traversal, Command Injection) and native C/C++ services (Buffer Overflows, unsafe string formatting, `system()` calls).
- ✅ **Syntactically Correct Patches**: Synthesizes minimal code diffs that preserve project coding style, AST validity, and existing functionality.
- ✅ **POV Elimination**: Confirms reproducible Proof-of-Vulnerability (POV) payloads and verifies their elimination post-patching.

### 2. Security Objectives
- ✅ **Causal Explanations**: Produces structured Causal Graph JSONs and narratives detailing input taint propagation $\to$ control/data flow $\to$ root cause sink.
- ✅ **Executable Security Contracts**: Compiles durable security knowledge into code-level assertions, targeted pytest suites (`test_contract_*.py`), and fuzzing oracles encoding safe invariant behavior.

### 3. Operational Objectives
- ✅ **Single-Command & Air-Gapped Deployment**: Deploys via single command (`python run_kalpa.py` / `./run_kalpa.sh`), air-gapped Docker container (`Dockerfile`), or local LLM inference (`Ollama` / `vLLM`).
- ✅ **Measurable Metrics**: Evaluated via [`eval_kalpa.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/eval_kalpa.py) recording Patch Success Rate (PSR), Mean Time to Repair (MTTR), and CPU/RAM/Token utilization.

---

## ⚡ System Architecture & Modules

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

### Module Summary
1. **Target Ingestion & Static Analysis**: [`kalpa/static_analysis/analyzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/analyzer.py)
2. **Dynamic Fuzzing & POV Generator**: [`kalpa/dynamic_analysis/fuzzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/fuzzer.py)
3. **Causal LLM Reasoning Engine**: [`kalpa/causal_engine/reasoner.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/reasoner.py) & [`local_provider.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/local_provider.py)
4. **Patch Synthesizer**: [`kalpa/patching/synthesizer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/patching/synthesizer.py)
5. **Security Contract Compiler**: [`kalpa/contract_compiler/compiler.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/compiler.py)
6. **Self-Adversarial Orchestrator**: [`kalpa/orchestrator/controller.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/orchestrator/controller.py)
7. **Defense Operations Web Dashboard**: [`kalpa/dashboard/app.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dashboard/app.py)

---

## 📊 Benchmark & Evaluation Results (`eval_report.json`)

| Target Service | Language | Found | Fixed | Patch Success Rate (PSR) | Mean Time to Repair (MTTR) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `vulnerable_service` | Python (Flask/SQLAlchemy) | 2 | 2 | **100.0%** | **2.51s** |
| `vulnerable_cpp_service` | C/C++ (GCC/ASan) | 4 | 2 | **50.0%** | **2.26s** |
| **TOTAL BENCHMARK** | **Multi-Language** | **6** | **4** | **66.7%** | **2.42s** |

---

## 🛡️ Defense-Ready Evidence Bundle Format

Every fix generates an auditable Evidence Bundle in `evidence_bundles/<VULN_ID>/`:
- `evidence_bundle.json`: Complete machine-readable findings, causal explanation, and metrics.
- `causal_explanation.md`: Causal narrative detailing root cause and taint path.
- `patch.diff`: Unified code diff.
- `test_contract_*.py`: Executable pytest security contract.

---

## 🚀 Deployment Modes

### 1. Interactive Defense Web Dashboard
```bash
python run_kalpa.py --dashboard
```
Access the warm off-white glassmorphism dashboard at **`http://127.0.0.1:8000`**.

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
