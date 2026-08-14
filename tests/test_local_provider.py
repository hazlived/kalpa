import unittest
from kalpa.causal_engine.local_provider import LocalLLMProvider

class TestLocalLLMProvider(unittest.TestCase):

    def test_provider_initialization(self):
        provider = LocalLLMProvider("http://localhost:11434", "deepseek-coder")
        self.assertEqual(provider.endpoint, "http://localhost:11434")
        self.assertEqual(provider.model_name, "deepseek-coder")

    def test_availability_check_resilient(self):
        # Unreachable local endpoint returns False without throwing exception
        provider = LocalLLMProvider("http://127.0.0.1:99999", "test-model")
        self.assertFalse(provider.is_available())

if __name__ == "__main__":
    unittest.main()
