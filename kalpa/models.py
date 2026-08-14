import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional

def normalize_to_utc_naive(dt: datetime.datetime) -> datetime.datetime:
    """
    SQLite / DB Ingestion helper: Normalize all datetimes to UTC-naive.
    Strips tzinfo after converting to UTC if tz-aware.
    """
    if dt is None:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    if dt.tzinfo is not None:
        return datetime.datetime(*dt.utctimetuple()[:6])
    return dt

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityClass(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    AUTH_BYPASS = "AUTH_BYPASS"
    UNSAFE_DESERIALIZATION = "UNSAFE_DESERIALIZATION"
    LOGIC_FLAW = "LOGIC_FLAW"
    OTHER = "OTHER"

@dataclass
class VulnerabilityFinding:
    id: str
    vulnerability_class: VulnerabilityClass
    severity: Severity
    file_path: str
    line_number: int
    function_name: str
    description: str
    taint_source: Optional[str] = None
    taint_sink: Optional[str] = None
    snippet: str = ""
    tool_source: str = "KALPA-SAST"
    cve_or_cwe: str = "CWE-UNKNOWN"

@dataclass
class POVPayload:
    finding_id: str
    input_type: str  # 'http_request', 'cli_args', 'function_call', 'payload_bytes'
    payload: str
    endpoint: Optional[str] = None
    expected_status_or_signal: Optional[str] = None
    crash_trace: str = ""
    confirmed: bool = False
    timestamp: str = field(default_factory=lambda: normalize_to_utc_naive(datetime.datetime.now(datetime.timezone.utc)).isoformat())

@dataclass
class CausalNode:
    id: str
    node_type: str  # 'input', 'control_flow', 'data_flow', 'sink', 'root_cause'
    label: str
    details: str
    code_location: str

@dataclass
class CandidateIntervention:
    id: str
    strategy_name: str
    description: str
    target_file: str
    pros: List[str]
    cons: List[str]
    expected_security_impact: str
    functional_safety_score: float  # 0.0 to 1.0

@dataclass
class CausalExplanation:
    finding_id: str
    vulnerability_class: VulnerabilityClass
    root_cause: str
    causal_narrative: str
    causal_nodes: List[CausalNode] = field(default_factory=list)
    interventions: List[CandidateIntervention] = field(default_factory=list)
    selected_intervention_id: Optional[str] = None

@dataclass
class SecurityContract:
    contract_id: str
    finding_id: str
    rule_name: str
    code_assertions: List[str] = field(default_factory=list)
    generated_test_code: str = ""
    fuzz_oracle_code: str = ""
    invariants: List[str] = field(default_factory=list)

@dataclass
class PatchResult:
    finding_id: str
    patch_diff: str
    target_file: str
    syntax_valid: bool
    regression_tests_passed: bool
    pov_eliminated: bool
    refuzz_passed: bool
    applied_successfully: bool
    error_message: Optional[str] = None

@dataclass
class ResourceMetrics:
    time_to_repair_seconds: float = 0.0
    fuzzing_duration_seconds: float = 0.0
    llm_calls_made: int = 0
    llm_tokens_used: int = 0
    peak_cpu_percent: float = 0.0
    peak_ram_mb: float = 0.0
    timestamp: str = field(default_factory=lambda: normalize_to_utc_naive(datetime.datetime.now(datetime.timezone.utc)).isoformat())

@dataclass
class EvidenceBundle:
    target_name: str
    vulnerability_id: str
    causal_explanation: CausalExplanation
    pov_payload: POVPayload
    patch_result: PatchResult
    security_contract: SecurityContract
    metrics: ResourceMetrics
    timestamp: str = field(default_factory=lambda: normalize_to_utc_naive(datetime.datetime.now(datetime.timezone.utc)).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
