import json
import os
from typing import List, Dict, Any, Optional
from kalpa.models import VulnerabilityFinding, VulnerabilityClass, Severity

class SarifParser:
    """
    Parser for SARIF 2.1.0 (Static Analysis Results Interchange Format)
    and JSON SAST reports from tools like Semgrep, Bandit, Pylint.
    """

    @staticmethod
    def parse_file(sarif_path: str) -> List[VulnerabilityFinding]:
        if not os.path.exists(sarif_path):
            return []
        
        try:
            with open(sarif_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return []

        findings: List[VulnerabilityFinding] = []
        
        # Check if standard SARIF
        if "runs" in data:
            for run in data["runs"]:
                tool_name = run.get("tool", {}).get("driver", {}).get("name", "SAST")
                results = run.get("results", [])
                for idx, res in enumerate(results):
                    rule_id = res.get("ruleId", f"RULE-{idx}")
                    msg = res.get("message", {}).get("text", "Static analysis finding")
                    level = res.get("level", "warning")
                    
                    severity = Severity.HIGH if level in ("error", "high") else (
                        Severity.MEDIUM if level in ("warning", "medium") else Severity.LOW
                    )
                    
                    cwe = "CWE-UNKNOWN"
                    v_class = SarifParser._map_rule_to_vulnerability_class(rule_id, msg)
                    
                    locations = res.get("locations", [])
                    file_path = "unknown"
                    line_num = 1
                    func_name = "unknown_func"
                    
                    if locations:
                        loc = locations[0]
                        phys = loc.get("physicalLocation", {})
                        artifact_loc = phys.get("artifactLocation", {})
                        file_path = artifact_loc.get("uri", "unknown")
                        region = phys.get("region", {})
                        line_num = region.get("startLine", 1)
                        
                        logical = loc.get("logicalLocations", [])
                        if logical:
                            func_name = logical[0].get("name", func_name)
                    
                    # Extract code slice snippet if available
                    snippet = res.get("analysisTarget", {}).get("uri", "")
                    
                    finding = VulnerabilityFinding(
                        id=f"FINDING-{len(findings)+1:03d}",
                        vulnerability_class=v_class,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_num,
                        function_name=func_name,
                        description=f"[{rule_id}] {msg}",
                        snippet=snippet,
                        tool_source=tool_name,
                        cve_or_cwe=cwe
                    )
                    findings.append(finding)
                    
        # Check if Bandit JSON format
        elif "results" in data and "metrics" in data:
            for res in data.get("results", []):
                v_class = SarifParser._map_rule_to_vulnerability_class(res.get("test_id", ""), res.get("issue_text", ""))
                sev_str = res.get("issue_severity", "MEDIUM").upper()
                severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.MEDIUM
                
                finding = VulnerabilityFinding(
                    id=f"BANDIT-{res.get('test_id', '000')}-{len(findings)+1}",
                    vulnerability_class=v_class,
                    severity=severity,
                    file_path=res.get("filename", "unknown"),
                    line_number=res.get("line_number", 1),
                    function_name="code_block",
                    description=res.get("issue_text", "Bandit finding"),
                    snippet=res.get("code", ""),
                    tool_source="Bandit",
                    cve_or_cwe=f"CWE-{res.get('issue_cwe', {}).get('id', 'UNKNOWN')}"
                )
                findings.append(finding)
                
        return findings

    @staticmethod
    def _map_rule_to_vulnerability_class(rule_id: str, msg: str) -> VulnerabilityClass:
        combined = f"{rule_id} {msg}".lower()
        if "sql" in combined or "injection" in combined and "sql" in combined:
            return VulnerabilityClass.SQL_INJECTION
        if "command" in combined or "exec" in combined or "subprocess" in combined or "os.system" in combined:
            return VulnerabilityClass.COMMAND_INJECTION
        if "path" in combined or "traversal" in combined or "file_path" in combined or "open" in combined:
            return VulnerabilityClass.PATH_TRAVERSAL
        if "buffer" in combined or "overflow" in combined or "bounds" in combined:
            return VulnerabilityClass.BUFFER_OVERFLOW
        if "auth" in combined or "login" in combined or "bypass" in combined or "token" in combined:
            return VulnerabilityClass.AUTH_BYPASS
        if "pickle" in combined or "yaml" in combined or "deserialize" in combined:
            return VulnerabilityClass.UNSAFE_DESERIALIZATION
        return VulnerabilityClass.LOGIC_FLAW
