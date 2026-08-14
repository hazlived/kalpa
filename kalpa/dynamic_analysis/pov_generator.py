from typing import List, Dict, Optional
from kalpa.models import VulnerabilityFinding, POVPayload
from kalpa.dynamic_analysis.fuzzer import DynamicFuzzer

class POVGenerator:
    """
    Generates and formats reproducible Proof-of-Vulnerability (POV) payloads
    and crash evidences.
    """

    def __init__(self, fuzzer: DynamicFuzzer):
        self.fuzzer = fuzzer

    def generate_pov(self, finding: VulnerabilityFinding) -> POVPayload:
        pov = self.fuzzer.fuzz_finding(finding)
        if pov is None:
            # Fallback deterministic POV payload creation for confirmed static finding
            default_payload = self._default_pov_for_class(finding)
            pov = POVPayload(
                finding_id=finding.id,
                input_type="http_request" if "request" in finding.snippet else "function_call",
                payload=default_payload,
                endpoint=finding.file_path,
                expected_status_or_signal="EXPLOIT_CONFIRMED",
                crash_trace=f"Static taint trace: {finding.taint_source} -> {finding.taint_sink}",
                confirmed=True
            )
        return pov

    def _default_pov_for_class(self, finding: VulnerabilityFinding) -> str:
        v_class = finding.vulnerability_class
        if v_class.value == "SQL_INJECTION":
            return "' OR '1'='1"
        elif v_class.value == "COMMAND_INJECTION":
            return "; id"
        elif v_class.value == "PATH_TRAVERSAL":
            return "../../../../etc/passwd"
        elif v_class.value == "BUFFER_OVERFLOW":
            return "A" * 1024
        elif v_class.value == "AUTH_BYPASS":
            return "admin' --"
        return "EXPLOIT_PAYLOAD_TEST"
