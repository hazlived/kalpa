import os
import ast
import re
import difflib
from typing import Tuple, Optional
from kalpa.models import VulnerabilityFinding, CausalExplanation, VulnerabilityClass, PatchResult

class PatchSynthesizer:
    """
    Synthesizes minimal, focused code diffs targeting the causal root cause of a vulnerability,
    preserving project code style and functionality.
    """

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)

    def synthesize_and_apply_patch(self, finding: VulnerabilityFinding, explanation: CausalExplanation) -> PatchResult:
        rel_path = finding.file_path
        full_path = os.path.join(self.target_dir, rel_path)
        
        if not os.path.exists(full_path):
            return PatchResult(
                finding_id=finding.id,
                patch_diff="",
                target_file=rel_path,
                syntax_valid=False,
                regression_tests_passed=False,
                pov_eliminated=False,
                refuzz_passed=False,
                applied_successfully=False,
                error_message=f"Target file {rel_path} not found"
            )

        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            original_code = f.read()

        patched_code, diff_text = self.generate_patched_code(original_code, finding, explanation)
        
        # Verify syntax validity
        syntax_ok = True
        err_msg = None
        if rel_path.endswith(".py"):
            try:
                ast.parse(patched_code, filename=full_path)
            except SyntaxError as e:
                syntax_ok = False
                err_msg = f"SyntaxError in synthesized patch: {e}"

        if syntax_ok:
            # Write back patched code
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(patched_code)

        return PatchResult(
            finding_id=finding.id,
            patch_diff=diff_text,
            target_file=rel_path,
            syntax_valid=syntax_ok,
            regression_tests_passed=False,
            pov_eliminated=False,
            refuzz_passed=False,
            applied_successfully=syntax_ok,
            error_message=err_msg
        )

    def generate_patched_code(self, original_code: str, finding: VulnerabilityFinding, explanation: CausalExplanation) -> Tuple[str, str]:
        lines = original_code.splitlines(keepends=True)
        line_idx = finding.line_number - 1
        
        if line_idx < 0 or line_idx >= len(lines):
            return original_code, ""

        target_line = lines[line_idx]
        vclass = finding.vulnerability_class

        replacement_lines = []

        if vclass == VulnerabilityClass.SQL_INJECTION:
            # Replace f-string or string formatted SQL query with parameterized query
            indent = len(target_line) - len(target_line.lstrip())
            indent_str = " " * indent
            
            if "execute(" in target_line or "query(" in target_line:
                # Parameterized SQL patch transformation
                if "f\"" in target_line or "f'" in target_line:
                    # Match query pattern like: query = f"SELECT * FROM users WHERE name = '{user}'"
                    patched_line = re.sub(r'f["\'](.*?)["\']', r'"\1"', target_line)
                    # Replace variable interpolation with ? or %s parameter placeholders
                    patched_line = re.sub(r"=\s*'\{(\w+)\}'", "= ?", patched_line)
                    patched_line = re.sub(r"=\s*\{(\w+)\}", "= ?", patched_line)
                    
                    # Pass params tuple
                    var_matches = re.findall(r"\{(\w+)\}", target_line)
                    if var_matches:
                        params_tuple = f"({', '.join(var_matches)},)"
                        patched_line = re.sub(r'\)\s*$', f', {params_tuple})\n', patched_line.rstrip()) + "\n"
                    replacement_lines.append(patched_line)
                else:
                    replacement_lines.append(f"{indent_str}# KALPA Security Patch: Parameterized query\n")
                    replacement_lines.append(target_line.replace("%", ","))

        elif vclass == VulnerabilityClass.COMMAND_INJECTION:
            indent = len(target_line) - len(target_line.lstrip())
            indent_str = " " * indent
            replacement_lines.append(f"{indent_str}# KALPA Security Patch: Sanitize command execution\n")
            replacement_lines.append(f"{indent_str}import shlex\n")
            if "os.system(" in target_line:
                replacement_lines.append(target_line.replace("os.system(", "subprocess.run(shlex.split(").replace(")", "), check=True)"))
            elif "subprocess.Popen(" in target_line or "subprocess.run(" in target_line:
                replacement_lines.append(target_line.replace("shell=True", "shell=False"))

        elif vclass == VulnerabilityClass.PATH_TRAVERSAL:
            indent = len(target_line) - len(target_line.lstrip())
            indent_str = " " * indent
            replacement_lines.append(f"{indent_str}# KALPA Security Patch: Canonical path traversal defense\n")
            replacement_lines.append(f"{indent_str}filename = os.path.basename(filename) if 'filename' in locals() else filename\n")
            replacement_lines.append(target_line)

        else:
            indent = len(target_line) - len(target_line.lstrip())
            indent_str = " " * indent
            replacement_lines.append(f"{indent_str}# KALPA Security Contract Assertion\n")
            replacement_lines.append(f"{indent_str}if not isinstance(user_input, str) or len(user_input) > 2048: raise ValueError('Invalid input')\n")
            replacement_lines.append(target_line)

        if not replacement_lines:
            replacement_lines = [target_line]

        new_lines = lines[:line_idx] + replacement_lines + lines[line_idx+1:]
        patched_code = "".join(new_lines)

        diff = "".join(difflib.unified_diff(
            lines,
            new_lines,
            fromfile=f"a/{finding.file_path}",
            tofile=f"b/{finding.file_path}",
            lineterm=""
        ))

        return patched_code, diff

    def revert_patch(self, rel_path: str, original_code: str):
        full_path = os.path.join(self.target_dir, rel_path)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(original_code)
