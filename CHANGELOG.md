# Changelog - KALPA: Causal Cyber Reasoning System

All notable changes to the KALPA framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-08-14

### Added
- **Native Local LLM Integration**: Added [`kalpa/causal_engine/local_provider.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/local_provider.py) supporting Ollama and vLLM local endpoints with zero external network connectivity.
- **Air-Gapped Provider Auto-Detection**: Integrated automatic local model discovery and fallback in `CausalReasoner`.
- **CLI Local Model Flags**: Added `--ollama-host` and `--model` CLI arguments to `run_kalpa.py`.
- **Local Provider Unit Tests**: Added unit test coverage in `tests/test_local_provider.py` (**8/8 tests OK**).

## [1.2.0] - 2026-08-14

### Added
- **Interactive Defense Operations Web Dashboard**: Built FastAPI backend (`kalpa/dashboard/app.py`) and Vanilla CSS/JS frontend with dark glassmorphism theme (`index.html`, `style.css`, `app.js`).
- **Interactive Causal Graph Visualizer**: Renders SVG nodes connecting taint sources, control flow transitions, and root cause sinks.
- **CLI Dashboard Launcher**: Added `--dashboard` flag to `run_kalpa.py` to start web dashboard on `http://127.0.0.1:8000`.

## [1.1.0] - 2026-08-14

### Added
- **Docker Containerization**: Added multi-stage [`Dockerfile`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/Dockerfile) and [`docker-compose.yml`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/docker-compose.yml) for single-command air-gapped deployment in defense environments.
- **Native C/C++ Target Support**: Added C/C++ benchmark target (`targets/vulnerable_cpp_service`), static buffer overflow/format string analyzer rule additions, and C/C++ patch synthesis logic (`strncpy`, `snprintf`).
- **AI Kavach Evaluation Suite (`eval_kalpa.py`)**: Built automated evaluation harness that runs KALPA across multiple targets and outputs AI Kavach KPIs: Patch Success Rate (PSR), MTTR, and resource utilization metrics.

## [1.0.0] - 2026-08-14

### Added
- **Core Orchestrator Controller**: End-to-end loop linking static intake, dynamic fuzzing, causal reasoning, patch synthesis, security contract compilation, and self-adversarial validation ([`kalpa/orchestrator/controller.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/orchestrator/controller.py)).
- **Static Analysis & Code Slicing**: SARIF 2.1.0 report parser, AST python scanning, C/C++ regex scanner, and line-slice extraction ([`kalpa/static_analysis/analyzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/analyzer.py), [`kalpa/static_analysis/sarif_parser.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/static_analysis/sarif_parser.py)).
- **Dynamic Fuzzing & POV Generator**: Multi-protocol payload mutation engine, dynamic harness runner, crash/trace analyzer, and reproducible Proof-of-Vulnerability payload generator ([`kalpa/dynamic_analysis/fuzzer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/fuzzer.py), [`kalpa/dynamic_analysis/pov_generator.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/dynamic_analysis/pov_generator.py)).
- **Causal Reasoning Engine (LLM Brain)**: Structured causal graph JSON builder, root cause identifier, and intervention ranking engine supporting API queries and standalone offline fallback ([`kalpa/causal_engine/reasoner.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/reasoner.py), [`kalpa/causal_engine/prompts.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/causal_engine/prompts.py)).
- **Patch Synthesis & Security Contract Compiler**: Synthesizes minimal code diffs and translates security knowledge into executable code assertions, targeted pytest contracts, and fuzzing oracles ([`kalpa/patching/synthesizer.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/patching/synthesizer.py), [`kalpa/contract_compiler/compiler.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/contract_compiler/compiler.py)).
- **Daemon File Watcher**: File-polling watcher adhering strictly to `(st_mtime, st_size)` signature tracking in `_file_seen_signature` to prevent duplicate re-read overhead ([`kalpa/utils/file_watcher.py`](file:///c:/Users/haziq/OneDrive/Documents/projects/kalpa/kalpa/utils/file_watcher.py)).
- **Benchmark Target Service**: Realistic target web microservice (`targets/vulnerable_service`) featuring SQL Injection, Path Traversal, Command Injection, SQLite UTC-naive datetimes, and SQLAlchemy `expunge_all()` read methods.
- **Single-Command CLI & Shell Entrypoints**: `run_kalpa.py` and `run_kalpa.sh` for single-command autonomous execution.
- **Evidence Bundle Generator**: Auditable export format producing JSON summaries, Markdown causal reports, diff files, and executable security contracts.
- **Comprehensive Unit & Integration Test Suite**: Complete unit tests covering all components (`tests/test_kalpa.py`).
