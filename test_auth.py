"""
test_auth.py
------------
Automated test suite for the Day 7 Secure Authentication System.
Run:
    python test_auth.py
Generates AUTH_TEST_REPORT.md with a pass/fail summary.
"""

from datetime import datetime
import app as flask_app_module

client = flask_app_module.app.test_client()
results = []


def record(name, condition, detail=""):
    results.append({"test": name, "passed": bool(condition), "detail": detail})
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}  {detail}")


def login(username, password, ip=None):
    headers = {"X-Forwarded-For": ip} if ip else {}
    r = client.post("/api/auth/login", headers=headers,
                     json={"username": username, "password": password})
    return r


# ---------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------
r = client.post("/api/auth/register",
                 json={"username": "qa_analyst", "password": "QaPass1234", "role": "analyst"})
record("Register new analyst (201)", r.status_code == 201, f"status={r.status_code}")

r = client.post("/api/auth/register",
                 json={"username": "qa_analyst", "password": "QaPass1234", "role": "analyst"})
record("Duplicate username rejected (422)", r.status_code == 422, f"status={r.status_code}")

r = client.post("/api/auth/register",
                 json={"username": "qa_weak", "password": "123", "role": "analyst"})
record("Weak password rejected (422)", r.status_code == 422, f"status={r.status_code}")

r = client.post("/api/auth/register",
                 json={"username": "qa_badrole", "password": "GoodPass123", "role": "superuser"})
record("Invalid role rejected (422)", r.status_code == 422, f"status={r.status_code}")

# ---------------------------------------------------------------------
# 2. Password hashing - never stored/returned in plaintext
# ---------------------------------------------------------------------
from auth.register import users
record("Password is bcrypt-hashed, not plaintext",
       users["qa_analyst"]["password_hash"] != b"QaPass1234"
       and users["qa_analyst"]["password_hash"].startswith(b"$2b$"),
       "hash starts with $2b$ (bcrypt)")

# ---------------------------------------------------------------------
# 3. Login - success and failure
# ---------------------------------------------------------------------
r = login("qa_analyst", "QaPass1234")
record("Correct credentials -> 200 with JWT", r.status_code == 200 and r.get_json()["data"]["token"],
       f"status={r.status_code}")
qa_token = r.get_json()["data"]["token"]

r = login("qa_analyst", "WrongPassword")
record("Wrong password -> 401", r.status_code == 401, f"status={r.status_code}")

r = login("nonexistent_user", "whatever123")
record("Unknown username -> 401 (no user enumeration)", r.status_code == 401, f"status={r.status_code}")

# ---------------------------------------------------------------------
# 4. Account locking after repeated failures
# ---------------------------------------------------------------------
client.post("/api/auth/register",
            json={"username": "qa_lockme", "password": "LockTest123", "role": "monitor"})
for _ in range(5):
    r = login("qa_lockme", "wrongpass")
record("5th failed attempt locks account (423)", r.status_code == 423, f"status={r.status_code}")

r = login("qa_lockme", "LockTest123")
record("Correct password still rejected while locked", r.status_code == 423, f"status={r.status_code}")

# ---------------------------------------------------------------------
# 5. Token-protected routes
# ---------------------------------------------------------------------
r = client.get("/api/threat-summary")
record("No token -> 401", r.status_code == 401, f"status={r.status_code}")

r = client.get("/api/threat-summary", headers={"Authorization": f"Bearer {qa_token}"})
record("Valid token -> 200", r.status_code == 200, f"status={r.status_code}")

r = client.get("/api/threat-summary", headers={"Authorization": "Bearer not-a-real-token"})
record("Malformed token -> 401", r.status_code == 401, f"status={r.status_code}")

# ---------------------------------------------------------------------
# 6. Role-based access control
# ---------------------------------------------------------------------
r = client.post("/api/block-ip", headers={"Authorization": f"Bearer {qa_token}"},
                 json={"ip": "10.0.0.99"})
record("Analyst forbidden from admin-only block-ip (403)", r.status_code == 403, f"status={r.status_code}")

r = login("monitor1", "MonitorPass123")
monitor_token = r.get_json()["data"]["token"]
r = client.get("/api/incident/whatever", headers={"Authorization": f"Bearer {monitor_token}"})
record("Monitor role denied incident/evidence access (403)", r.status_code == 403, f"status={r.status_code}")

# ---------------------------------------------------------------------
# 7. Logout / session revocation
# ---------------------------------------------------------------------
r = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {qa_token}"})
record("Logout succeeds (200)", r.status_code == 200, f"status={r.status_code}")

r = client.get("/api/threat-summary", headers={"Authorization": f"Bearer {qa_token}"})
record("Token rejected immediately after logout", r.status_code == 401, f"status={r.status_code}")

# ---------------------------------------------------------------------
# 8. IP-based login restriction
# ---------------------------------------------------------------------
test_ip = "198.51.100.200"
for i in range(9):
    r = login(f"ghost{i % 4}", "wrong", ip=test_ip)
record("IP blocked after repeated failed logins (429)", r.status_code == 429, f"status={r.status_code}")

# ---------------------------------------------------------------------
# 9. Admin account management
# ---------------------------------------------------------------------
r = login("admin", "AdminPass123")
admin_token = r.get_json()["data"]["token"]

r = client.post("/api/auth/users/qa_analyst/lock", headers={"Authorization": f"Bearer {admin_token}"})
record("Admin can disable a user account", r.status_code == 200, f"status={r.status_code}")

r = login("qa_analyst", "QaPass1234")
record("Disabled account cannot log in (403)", r.status_code == 403, f"status={r.status_code}")

r = client.post("/api/auth/users/qa_analyst/unlock", headers={"Authorization": f"Bearer {admin_token}"})
record("Admin can re-enable a user account", r.status_code == 200, f"status={r.status_code}")

# ---------------------------------------------------------------------
# 10. Authentication logging / timeline
# ---------------------------------------------------------------------
r = client.get("/api/auth/logs", headers={"Authorization": f"Bearer {admin_token}"})
record("Auth timeline accessible to admin", r.status_code == 200 and len(r.get_json()["data"]) > 0,
       f"entries={len(r.get_json()['data']) if r.status_code==200 else 0}")

r = client.get("/api/auth/logs", headers={"Authorization": f"Bearer {monitor_token}"})
record("Auth timeline forbidden to non-admin (403)", r.status_code == 403, f"status={r.status_code}")

# ---------------------------------------------------------------------
# WRITE REPORT
# ---------------------------------------------------------------------
passed = sum(1 for t in results if t["passed"])
total = len(results)

lines = [
    "# Authentication System — Test Report",
    "",
    f"**Generated:** {datetime.utcnow().isoformat()}Z",
    f"**Result:** {passed}/{total} tests passed",
    "",
    "| # | Test Case | Result | Detail |",
    "|---|-----------|--------|--------|",
]
for i, t in enumerate(results, 1):
    mark = "PASS" if t["passed"] else "FAIL"
    lines.append(f"| {i} | {t['test']} | {mark} | {t['detail']} |")

with open("AUTH_TEST_REPORT.md", "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"\n{passed}/{total} tests passed. Report written to AUTH_TEST_REPORT.md")
