# Authentication System — Test Report

**Generated:** 2026-06-20T04:15:08.570272Z
**Result:** 23/23 tests passed

| # | Test Case | Result | Detail |
|---|-----------|--------|--------|
| 1 | Register new analyst (201) | PASS | status=201 |
| 2 | Duplicate username rejected (422) | PASS | status=422 |
| 3 | Weak password rejected (422) | PASS | status=422 |
| 4 | Invalid role rejected (422) | PASS | status=422 |
| 5 | Password is bcrypt-hashed, not plaintext | PASS | hash starts with $2b$ (bcrypt) |
| 6 | Correct credentials -> 200 with JWT | PASS | status=200 |
| 7 | Wrong password -> 401 | PASS | status=401 |
| 8 | Unknown username -> 401 (no user enumeration) | PASS | status=401 |
| 9 | 5th failed attempt locks account (423) | PASS | status=423 |
| 10 | Correct password still rejected while locked | PASS | status=423 |
| 11 | No token -> 401 | PASS | status=401 |
| 12 | Valid token -> 200 | PASS | status=200 |
| 13 | Malformed token -> 401 | PASS | status=401 |
| 14 | Analyst forbidden from admin-only block-ip (403) | PASS | status=403 |
| 15 | Monitor role denied incident/evidence access (403) | PASS | status=403 |
| 16 | Logout succeeds (200) | PASS | status=200 |
| 17 | Token rejected immediately after logout | PASS | status=401 |
| 18 | IP blocked after repeated failed logins (429) | PASS | status=429 |
| 19 | Admin can disable a user account | PASS | status=200 |
| 20 | Disabled account cannot log in (403) | PASS | status=403 |
| 21 | Admin can re-enable a user account | PASS | status=200 |
| 22 | Auth timeline accessible to admin | PASS | entries=42 |
| 23 | Auth timeline forbidden to non-admin (403) | PASS | status=403 |
