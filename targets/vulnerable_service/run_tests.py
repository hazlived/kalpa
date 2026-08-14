import os
import sys
import datetime
from app import UserService, read_user_document, normalize_to_utc_naive

def run_all_tests():
    print("Running target regression test harness...")
    
    # Test 1: User Service ORM read & datetime normalization
    svc = UserService()
    user = svc.get_user_by_id(1)
    assert user is not None, "Failed to load user 1"
    assert user.username == "admin", "User 1 should be admin"
    
    dt = normalize_to_utc_naive(datetime.datetime.now(datetime.timezone.utc))
    assert dt.tzinfo is None, "SQLite datetime must be UTC-naive"
    
    # Test 2: Safe document reading
    doc = read_user_document("readme.txt")
    assert "KALPA Target Service" in doc, "Document read failed"

    # Test 3: Payload execution environment check
    payload = os.getenv("TEST_PAYLOAD")
    if payload:
        if "' OR '" in payload or "UNION" in payload:
            res = svc.search_users_raw(payload)
            if len(res) > 1 or payload in str(res):
                print("EXPLOIT_CONFIRMED: SQL Injection reproduced")
                sys.exit(1)
        elif "../" in payload or "..\\" in payload:
            try:
                read_user_document(payload)
                print("EXPLOIT_CONFIRMED: Path Traversal reproduced")
                sys.exit(1)
            except Exception:
                pass

    print("All target regression tests passed cleanly!")
    sys.exit(0)

if __name__ == "__main__":
    run_all_tests()
