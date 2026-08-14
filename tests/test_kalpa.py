import os
import tempfile
import unittest
import datetime
from kalpa.config import KalpaConfig, ResourceBudget
from kalpa.models import (
    VulnerabilityFinding, VulnerabilityClass, Severity,
    normalize_to_utc_naive
)
from kalpa.static_analysis.analyzer import StaticAnalyzer
from kalpa.dynamic_analysis.fuzzer import DynamicFuzzer
from kalpa.dynamic_analysis.pov_generator import POVGenerator
from kalpa.causal_engine.reasoner import CausalReasoner
from kalpa.patching.synthesizer import PatchSynthesizer
from kalpa.contract_compiler.compiler import SecurityContractCompiler
from kalpa.utils.file_watcher import FileWatcherDaemon
from kalpa.orchestrator.controller import KalpaController

class TestKalpaFramework(unittest.TestCase):

    def setUp(self):
        self.target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "targets", "vulnerable_service"))
        self.config = KalpaConfig(project_root=self.target_dir, llm_provider="rule_based")

    def test_utc_naive_datetime_normalizer(self):
        """Test SQLite rule: Normalize datetimes to UTC-naive."""
        tz_aware = datetime.datetime.now(datetime.timezone.utc)
        normalized = normalize_to_utc_naive(tz_aware)
        self.assertIsNone(normalized.tzinfo)
        self.assertEqual(normalized.year, tz_aware.year)

    def test_file_watcher_signature_tracking(self):
        """Test File-Polling daemon rule: Track (st_mtime, st_size) in _file_seen_signature."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            watcher = FileWatcherDaemon(tmp_dir)
            test_file = os.path.join(tmp_dir, "test.txt")
            with open(test_file, "w") as f:
                f.write("initial content")

            # First poll detects new file
            updated = watcher.poll_updates()
            self.assertIn(test_file, updated)
            self.assertIn(test_file, watcher._file_seen_signature)

            # Second poll without changes skips re-read
            updated_second = watcher.poll_updates()
            self.assertEqual(len(updated_second), 0)

    def test_static_analyzer(self):
        """Test static scanning and code slicing."""
        analyzer = StaticAnalyzer(self.target_dir)
        findings = analyzer.run_analysis()
        self.assertGreater(len(findings), 0)
        
        finding = findings[0]
        code_slice = analyzer.get_code_slice(finding.file_path, finding.line_number)
        self.assertIn("|", code_slice)

    def test_causal_reasoner_and_contract_compiler(self):
        """Test Causal Reasoning Engine and Security Contract Compiler."""
        finding = VulnerabilityFinding(
            id="TEST-FINDING-001",
            vulnerability_class=VulnerabilityClass.SQL_INJECTION,
            severity=Severity.HIGH,
            file_path="app.py",
            line_number=50,
            function_name="search_users_raw",
            description="SQL Injection test",
            snippet="query = f\"SELECT * FROM users WHERE username = '{search_query}'\""
        )
        fuzzer = DynamicFuzzer(self.target_dir, self.config.budget)
        pov_gen = POVGenerator(fuzzer)
        pov = pov_gen.generate_pov(finding)

        reasoner = CausalReasoner(self.config)
        explanation = reasoner.analyze(finding, "code_slice_placeholder", pov)

        self.assertEqual(explanation.vulnerability_class, VulnerabilityClass.SQL_INJECTION)
        self.assertGreater(len(explanation.causal_nodes), 0)

        compiler = SecurityContractCompiler(self.target_dir)
        contract = compiler.compile_contract(finding, explanation, pov)
        self.assertEqual(contract.finding_id, "TEST-FINDING-001")
        self.assertIn("pytest", contract.generated_test_code)

    def test_end_to_end_controller(self):
        """Test full end-to-end autonomous controller loop."""
        controller = KalpaController(self.target_dir, self.config)
        bundles = controller.run_autonomous_loop()
        self.assertGreater(len(bundles), 0)
        first_bundle = bundles[0]
        self.assertIsNotNone(first_bundle.patch_result)
        self.assertIsNotNone(first_bundle.security_contract)

if __name__ == "__main__":
    unittest.main()
