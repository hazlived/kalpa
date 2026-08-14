import os
import tempfile
import unittest
from kalpa.dynamic_analysis.c_harness_generator import CHarnessGenerator
from kalpa.contract_compiler.cicd_exporter import CICDContractExporter
from kalpa.models import SecurityContract

class TestPhase9Modules(unittest.TestCase):

    def test_c_harness_generator(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            generator = CHarnessGenerator(tmp_dir)
            harness_path = generator.generate_harness("main.c", "process_user_input")
            self.assertTrue(os.path.exists(harness_path))
            with open(harness_path, "r") as f:
                content = f.read()
                self.assertIn("LLVMFuzzerTestOneInput", content)
                self.assertIn("process_user_input", content)

    def test_cicd_exporter(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            exporter = CICDContractExporter(tmp_dir)
            contract = SecurityContract(
                contract_id="CONTRACT-001",
                finding_id="FINDING-001",
                rule_name="Prevent_SQLi"
            )
            wf_path = exporter.export_github_action([contract])
            self.assertTrue(os.path.exists(wf_path))
            with open(wf_path, "r") as f:
                content = f.read()
                self.assertIn("pytest", content)
                self.assertIn("CONTRACT-001", content)

if __name__ == "__main__":
    unittest.main()
