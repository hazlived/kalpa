import json
import urllib.request
import urllib.parse
from typing import Optional, Dict, Any

class LocalLLMProvider:
    """
    Air-Gapped Local LLM Provider for Ollama and vLLM inference engines.
    Queries local endpoints (e.g. http://localhost:11434) with structured JSON schemas.
    """

    def __init__(self, endpoint: str = "http://localhost:11434", model_name: str = "deepseek-coder"):
        self.endpoint = endpoint.rstrip("/")
        self.model_name = model_name

    def is_available(self) -> bool:
        """Checks if the local Ollama/vLLM endpoint is online."""
        try:
            url = f"{self.endpoint}/api/tags" if "11434" in self.endpoint else f"{self.endpoint}/v1/models"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status == 200
        except Exception:
            return False

    def query(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Queries local Ollama or vLLM server and returns JSON response text."""
        if "11434" in self.endpoint:
            return self._query_ollama(system_prompt, user_prompt)
        else:
            return self._query_openai_compatible(system_prompt, user_prompt)

    def _query_ollama(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        url = f"{self.endpoint}/api/chat"
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1}
        }
        
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("message", {}).get("content")
        except Exception:
            return None

    def _query_openai_compatible(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        url = f"{self.endpoint}/v1/chat/completions"
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("choices", [])[0].get("message", {}).get("content")
        except Exception:
            return None
