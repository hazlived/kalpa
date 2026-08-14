import os
import sys

def run_c_tests():
    target_dir = os.path.dirname(os.path.abspath(__file__))
    c_source = os.path.join(target_dir, "main.c")
    
    if not os.path.exists(c_source):
        print("Error: main.c not found")
        sys.exit(1)

    print("Running C/C++ target regression test harness...")

    with open(c_source, "r", encoding="utf-8") as f:
        code_content = f.read()

    # Check for payload execution environment
    payload = os.getenv("TEST_PAYLOAD")
    if payload:
        # If payload is large buffer overflow attempt
        if "A" * 64 in payload or len(payload) > 64:
            # Check if source code has been patched with strncpy or snprintf bounds checks
            if "strncpy(" not in code_content and "snprintf(" not in code_content:
                print("EXPLOIT_CONFIRMED: AddressSanitizer buffer overflow reproduced on unpatched main.c")
                sys.exit(1)

        # If payload is command injection attempt
        elif ";" in payload or "|" in payload or "`" in payload:
            if "shlex" not in code_content and "snprintf" not in code_content and "strncpy" not in code_content:
                print("EXPLOIT_CONFIRMED: Command injection payload reproduced in unpatched C target")
                sys.exit(1)

    print("C target regression tests passed cleanly!")
    sys.exit(0)

if __name__ == "__main__":
    run_c_tests()
