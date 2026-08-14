import os
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class ResourceBudget:
    max_fuzz_seconds: int = 60
    max_llm_calls: int = 10
    max_token_budget: int = 100000
    cpu_limit_percent: float = 80.0
    ram_limit_mb: int = 2048
    llm_calls_made: int = 0
    llm_tokens_used: int = 0

@dataclass
class KalpaConfig:
    project_root: str = "."
    output_dir: str = "evidence_bundles"
    llm_provider: str = "auto"  # 'openai', 'anthropic', 'gemini', 'ollama', 'vllm', or 'rule_based'
    llm_api_key: Optional[str] = field(default_factory=lambda: os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY")))
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4o")
    ollama_endpoint: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    local_model_name: str = os.getenv("LOCAL_MODEL", "deepseek-coder")
    budget: ResourceBudget = field(default_factory=ResourceBudget)
    enable_sanitizers: bool = True
    verbose: bool = True
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KalpaConfig":
        budget_data = data.pop("budget", {})
        budget = ResourceBudget(**budget_data) if isinstance(budget_data, dict) else ResourceBudget()
        return cls(budget=budget, **data)
