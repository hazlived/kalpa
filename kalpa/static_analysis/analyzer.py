import ast
import os
import re
from typing import List, Dict, Any, Optional, Tuple
from kalpa.models import VulnerabilityFinding, VulnerabilityClass, Severity
from kalpa.static_analysis.sarif_parser import SarifParser

class StaticAnalyzer:
    """
    Static analysis module providing automated code scanning, call graph extraction,
    code slicing around sensitive sinks, and SARIF report intake.
    """

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)

    def run_analysis(self, sarif_report_path: Optional[str] = None) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        
        # 1. Intake existing SARIF / SAST reports if provided
        if sarif_report_path and os.path.exists(sarif_report_path):
            sarif_findings = SarifParser.parse_file(sarif_report_path)
            findings.extend(sarif_findings)
            
        # 2. Dynamic AST + Pattern scanning fallback for target codebase files
        scanned_findings = self.scan_codebase()
        findings.extend(scanned_findings)

        # De-duplicate findings by file + line + class
        unique_findings: Dict[str, VulnerabilityFinding] = {}
        for f in findings:
            key = f"{f.file_path}:{f.line_number}:{f.vulnerability_class.value}"
            if key not in unique_findings:
                unique_findings[key] = f

        # Prioritize by severity
        result = list(unique_findings.values())
        result.sort(key=lambda x: (
            0 if x.severity == Severity.CRITICAL else (
                1 if x.severity == Severity.HIGH else (
                    2 if x.severity == Severity.MEDIUM else 3
                )
            )
        ))
        return result

    def scan_codebase(self) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.target_dir)
                    file_findings = self._scan_python_file(full_path, rel_path)
                    findings.extend(file_findings)
                elif file.endswith((".c", ".cpp", ".h")):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.target_dir)
                    file_findings = self._scan_cpp_file(full_path, rel_path)
                    findings.extend(file_findings)

        return findings

    def _scan_python_file(self, full_path: str, rel_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return []

        # Check for AST-level flaws
        try:
            tree = ast.parse(content, filename=full_path)
            for node in ast.walk(tree):
                # Raw SQL String format/concatenation
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    
                    if func_name in ("execute", "executemany", "raw_query", "query"):
                        for arg in node.args:
                            if isinstance(arg, (ast.BinOp, ast.JoinedStr, ast.Call)):
                                snippet = lines[node.lineno-1] if 0 <= node.lineno-1 < len(lines) else ""
                                findings.append(VulnerabilityFinding(
                                    id=f"SAST-SQLI-{rel_path}-{node.lineno}",
                                    vulnerability_class=VulnerabilityClass.SQL_INJECTION,
                                    severity=Severity.HIGH,
                                    file_path=rel_path,
                                    line_number=node.lineno,
                                    function_name=func_name,
                                    description="SQL query constructed using string formatting/concatenation instead of parameterized query.",
                                    taint_source="request_args",
                                    taint_sink=func_name,
                                    snippet=snippet,
                                    cve_or_cwe="CWE-89"
                                ))
                                
                    # Command Injection
                    if func_name in ("system", "popen", "call", "run", "Popen", "eval", "exec"):
                        snippet = lines[node.lineno-1] if 0 <= node.lineno-1 < len(lines) else ""
                        findings.append(VulnerabilityFinding(
                            id=f"SAST-CMDI-{rel_path}-{node.lineno}",
                            vulnerability_class=VulnerabilityClass.COMMAND_INJECTION,
                            severity=Severity.CRITICAL,
                            file_path=rel_path,
                            line_number=node.lineno,
                            function_name=func_name,
                            description=f"Potential command injection via unsafe call to '{func_name}'.",
                            taint_source="input_parameter",
                            taint_sink=func_name,
                            snippet=snippet,
                            cve_or_cwe="CWE-78"
                        ))
        except Exception:
            pass

        # Regex fallback for path traversal & unvalidated file reads
        for line_idx, line in enumerate(lines, start=1):
            if ("open(" in line or "os.path.join" in line or "send_file(" in line) and ("request." in line or "filename" in line or "user_input" in line or "user_path" in line):
                if "../" in line or "safe_join" not in line and "abspath" not in line:
                    findings.append(VulnerabilityFinding(
                        id=f"SAST-PATHTRAV-{rel_path}-{line_idx}",
                        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_number=line_idx,
                        function_name="file_handler",
                        description="Potential path traversal vulnerability: file opened with unvalidated path.",
                        taint_source="request_param",
                        taint_sink="open",
                        snippet=line.strip(),
                        cve_or_cwe="CWE-22"
                    ))

        return findings

    def _scan_cpp_file(self, full_path: str, rel_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        unsafe_cpp_funcs = {
            "strcpy": ("CWE-120", VulnerabilityClass.BUFFER_OVERFLOW, Severity.CRITICAL, "Unbounded buffer copy with strcpy"),
            "gets": ("CWE-242", VulnerabilityClass.BUFFER_OVERFLOW, Severity.CRITICAL, "Extremely unsafe function gets()"),
            "sprintf": ("CWE-134", VulnerabilityClass.BUFFER_OVERFLOW, Severity.HIGH, "Potential buffer overflow via sprintf"),
            "system": ("CWE-78", VulnerabilityClass.COMMAND_INJECTION, Severity.CRITICAL, "Unsafe system() call"),
        }

        for idx, line in enumerate(lines, start=1):
            for func, (cwe, vclass, sev, desc) in unsafe_cpp_funcs.items():
                if re.search(r'\b' + func + r'\s*\(', line):
                    findings.append(VulnerabilityFinding(
                        id=f"SAST-CPP-{func}-{rel_path}-{idx}",
                        vulnerability_class=vclass,
                        severity=sev,
                        file_path=rel_path,
                        line_number=idx,
                        function_name=func,
                        description=f"{desc}: {line.strip()}",
                        snippet=line.strip(),
                        cve_or_cwe=cwe
                    ))

        return findings

    def get_code_slice(self, rel_file_path: str, line_number: int, context_lines: int = 15) -> str:
        """Extract code slice around a specific line number for LLM context."""
        full_path = os.path.join(self.target_dir, rel_file_path)
        if not os.path.exists(full_path):
            return ""
        
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            start = max(0, line_number - 1 - context_lines)
            end = min(len(lines), line_number - 1 + context_lines + 1)
            
            sliced_lines = []
            for idx in range(start, end):
                prefix = " > " if idx == line_number - 1 else "   "
                sliced_lines.append(f"{prefix}{idx+1:4d} | {lines[idx].rstrip()}")
            return "\n".join(sliced_lines)
        except Exception:
            return ""
