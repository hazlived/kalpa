import json
import os
import urllib.request
import urllib.parse
from typing import Optional, Dict, Any, List
from kalpa.config import KalpaConfig
from kalpa.models import (
    VulnerabilityFinding, POVPayload, CausalExplanation,
    CausalNode, CandidateIntervention, VulnerabilityClass, Severity
)
from kalpa.causal_engine.prompts import SYSTEM_CAUSAL_PROMPT, USER_CAUSAL_REASONING_PROMPT
from kalpa.causal_engine.local_provider import LocalLLMProvider

class CausalReasoner:
    """
    KALPA Causal Reasoning Engine (LLM Brain).
    Ingests static findings, dynamic traces, and code slices to build
    a causal model of vulnerability propagation and propose root-cause interventions.
    """

    def __init__(self, config: KalpaConfig):
        self.config = config
        self.local_provider = LocalLLMProvider(
            endpoint=config.ollama_endpoint,
            model_name=config.local_model_name
        )

    def analyze(self, finding: VulnerabilityFinding, code_slice: str, pov: POVPayload) -> CausalExplanation:
        """
        Runs causal reasoning on a vulnerability finding.
        Attempts LLM query if configured, falling back to deterministic causal reasoning engine.
        """
        self.config.budget.llm_calls_made += 1
        
        # 1. Local Air-Gapped LLM Mode (Ollama / vLLM)
        if self.config.llm_provider in ("ollama", "vllm", "local") or (self.config.llm_provider == "auto" and self.local_provider.is_available()):
            try:
                prompt = USER_CAUSAL_REASONING_PROMPT.format(
                    finding_id=finding.id,
                    v_class=finding.vulnerability_class.value,
                    severity=finding.severity.value,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    function_name=finding.function_name,
                    description=finding.description,
                    cwe=finding.cve_or_cwe,
                    code_slice=code_slice,
                    pov_payload=pov.payload,
                    crash_trace=pov.crash_trace
                )
                res = self.local_provider.query(SYSTEM_CAUSAL_PROMPT, prompt)
                if res:
                    return self._parse_llm_json(finding, res)
            except Exception as e:
                if self.config.verbose:
                    print(f"[KALPA-LOCAL-LLM] Note: Local provider query failed: {e}")

        # 2. Remote API Query (OpenAI / Gemini)
        if self.config.llm_api_key and self.config.llm_provider not in ("rule_based", "ollama", "vllm"):
            try:
                llm_response = self._query_llm_api(finding, code_slice, pov)
                if llm_response:
                    return self._parse_llm_json(finding, llm_response)
            except Exception as e:
                if self.config.verbose:
                    print(f"[KALPA-LLM] Note: API query fallback to deterministic engine: {e}")

        # 3. Deterministic / Offline Causal Cyber Reasoning Engine
        return self._rule_based_causal_reasoning(finding, code_slice, pov)

    def _query_llm_api(self, finding: VulnerabilityFinding, code_slice: str, pov: POVPayload) -> Optional[str]:
        prompt = USER_CAUSAL_REASONING_PROMPT.format(
            finding_id=finding.id,
            v_class=finding.vulnerability_class.value,
            severity=finding.severity.value,
            file_path=finding.file_path,
            line_number=finding.line_number,
            function_name=finding.function_name,
            description=finding.description,
            cwe=finding.cve_or_cwe,
            code_slice=code_slice,
            pov_payload=pov.payload,
            crash_trace=pov.crash_trace
        )
        
        # Standard OpenAI-compatible API client via urllib
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.llm_api_key}"
        }
        data = {
            "model": self.config.llm_model,
            "messages": [
                {"role": "system", "content": SYSTEM_CAUSAL_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        }
        
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            self.config.budget.llm_tokens_used += body.get("usage", {}).get("total_tokens", 500)
            return body["choices"][0]["message"]["content"]

    def _parse_llm_json(self, finding: VulnerabilityFinding, raw_json: str) -> CausalExplanation:
        data = json.loads(raw_json)
        nodes = [CausalNode(**n) for n in data.get("causal_nodes", [])]
        interventions = [CandidateIntervention(**i) for i in data.get("interventions", [])]
        
        return CausalExplanation(
            finding_id=finding.id,
            vulnerability_class=finding.vulnerability_class,
            root_cause=data.get("root_cause", "Unsafe input flow"),
            causal_narrative=data.get("causal_narrative", "Causal path verified"),
            causal_nodes=nodes,
            interventions=interventions,
            selected_intervention_id=data.get("selected_intervention_id", "interv-1")
        )

    def _rule_based_causal_reasoning(self, finding: VulnerabilityFinding, code_slice: str, pov: POVPayload) -> CausalExplanation:
        vclass = finding.vulnerability_class
        
        if vclass == VulnerabilityClass.SQL_INJECTION:
            root_cause = "Direct string formatting/concatenation of unparsed user parameters into raw SQL query."
            narrative = f"Untrusted input payload '{pov.payload}' flows from endpoint into query handler function '{finding.function_name}', breaking SQL parser syntax boundaries."
            nodes = [
                CausalNode("node-1", "input", "HTTP Request Parameter", f"Taint payload '{pov.payload}' received", f"{finding.file_path}:{finding.line_number}"),
                CausalNode("node-2", "data_flow", "String Formatting Concatenation", "Query string constructed via f-string or % formatting", f"{finding.file_path}:{finding.line_number}"),
                CausalNode("node-3", "root_cause", "Unparameterized Database Execution", "Database driver executes raw unescaped query string", f"{finding.file_path}:{finding.line_number}")
            ]
            interventions = [
                CandidateIntervention(
                    id="interv-1",
                    strategy_name="Parameterized Query Interventions",
                    description="Replace string interpolation with parameterized SQL query bindings or SQLAlchemy ORM query methods.",
                    target_file=finding.file_path,
                    pros=["Completely removes SQL syntax injection risk", "Preserves query performance"],
                    cons=["Requires updating query signature"],
                    expected_security_impact="ROOT_CAUSE_REMOVAL",
                    functional_safety_score=0.99
                )
            ]
        elif vclass == VulnerabilityClass.COMMAND_INJECTION:
            root_cause = "Execution of shell commands using string concatenation with unsanitized user inputs."
            narrative = f"User payload '{pov.payload}' flows directly into shell invocation ({finding.function_name}), enabling arbitrary command execution."
            nodes = [
                CausalNode("node-1", "input", "User Argument Intake", f"Payload '{pov.payload}' passed to CLI/API", f"{finding.file_path}:{finding.line_number}"),
                CausalNode("node-2", "root_cause", "Unsafe Subprocess/System Shell Call", f"Call to '{finding.function_name}' with shell=True or unescaped string", f"{finding.file_path}:{finding.line_number}")
            ]
            interventions = [
                CandidateIntervention(
                    id="interv-1",
                    strategy_name="Subprocess List Argument Isolation & Shlex Escaping",
                    description="Pass command arguments as an isolated list with shell=False or apply strict input shlex escaping.",
                    target_file=finding.file_path,
                    pros=["Prevents command shell chaining", "Clean execution model"],
                    cons=["Requires list parsing"],
                    expected_security_impact="ROOT_CAUSE_REMOVAL",
                    functional_safety_score=0.97
                )
            ]
        elif vclass == VulnerabilityClass.PATH_TRAVERSAL:
            root_cause = "Unvalidated file system path resolution allowing directory traversal sequences (../)."
            narrative = f"User path parameter containing '{pov.payload}' is passed to open() or send_file() without canonicalization or root boundary validation."
            nodes = [
                CausalNode("node-1", "input", "Path Parameter Input", f"Relative path '{pov.payload}' supplied", f"{finding.file_path}:{finding.line_number}"),
                CausalNode("node-2", "root_cause", "Unbounded File Resolution", "File path opened directly without resolving realpath against base directory", f"{finding.file_path}:{finding.line_number}")
            ]
            interventions = [
                CandidateIntervention(
                    id="interv-1",
                    strategy_name="Canonical Path Resolution & Strict Base Sandbox Check",
                    description="Resolve target path via os.path.abspath / Path.resolve() and verify it starts with base directory, or use secure path sanitization.",
                    target_file=finding.file_path,
                    pros=["Absolute boundary enforcement", "Completely blocks traversal"],
                    cons=["Rejects out-of-bounds files"],
                    expected_security_impact="ROOT_CAUSE_REMOVAL",
                    functional_safety_score=0.99
                )
            ]
        else:
            root_cause = f"Unvalidated control/data flow in {finding.function_name} leading to security violation."
            narrative = f"Input payload propagates through {finding.file_path}:{finding.line_number} causing runtime vulnerability."
            nodes = [
                CausalNode("node-1", "input", "Untrusted Data Intake", f"Payload '{pov.payload}'", f"{finding.file_path}:{finding.line_number}"),
                CausalNode("node-2", "root_cause", "Missing Security Boundary", "Input boundary check missing", f"{finding.file_path}:{finding.line_number}")
            ]
            interventions = [
                CandidateIntervention(
                    id="interv-1",
                    strategy_name="Input Validation & Boundary Assertion",
                    description="Enforce strict input type, length, and range checks before operation.",
                    target_file=finding.file_path,
                    pros=["Prevents illegal state transitions"],
                    cons=["Requires validation logic"],
                    expected_security_impact="HIGH",
                    functional_safety_score=0.95
                )
            ]

        return CausalExplanation(
            finding_id=finding.id,
            vulnerability_class=vclass,
            root_cause=root_cause,
            causal_narrative=narrative,
            causal_nodes=nodes,
            interventions=interventions,
            selected_intervention_id="interv-1"
        )
