# Changelog - KALPA: Causal Cyber Reasoning System

All notable changes to the KALPA framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
