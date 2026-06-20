 Secure Analyst Authentication & Threat Access Control

Adds a full authentication layer (bcrypt password hashing, JWT sessions, RBAC,
account lockout, IP-based login restriction, and authentication logging) on
top of the Day 6 Threat Intelligence Backend, and uses it to protect every
threat API.

## Project structure

```
day7_secure_auth/
├── app.py                  Main Flask app — wires auth + threat-intel APIs together
├── auth/
│   ├── register.py         User registration + bcrypt password hashing
│   ├── login.py             Login validation, failed-attempt tracking, account
│   │                        locking, IP-based login restriction, suspicious-
│   │                        auth-pattern detection
│   ├── logout.py            Secure logout (server-side session revocation)
│   ├── session_manager.py  JWT issuance/validation, session timeout, active
│   │                        session tracking
│   ├── role_manager.py     RBAC role definitions (admin / analyst / monitor)
│   └── access_control.py   @jwt_required decorator — protects every route
├── auth/auth_logs.py       Authentication timeline / audit logging
├── templates/dashboard.html  Live dashboard with a real login screen
├── requirements.txt
├── test_auth.py             23-test automated suite -> AUTH_TEST_REPORT.md
└── README.md
```

> `flask-login` is included in `requirements.txt` per the lab's required
> libraries, but this implementation uses **JWT (PyJWT)** for the actual API
> authentication rather than Flask-Login's cookie/session model — JWT is the
> right fit here because Exercise 7.1 specifically asks for **JWT-protected
> threat APIs**, and a stateless REST API is normally authenticated with
> bearer tokens, not server-rendered session cookies.

## How to run

```bash
pip install -r requirements.txt
python app.py
```

Open the dashboard:
```
http://127.0.0.1:5000/dashboard
```

You'll land on a real login screen. Three demo accounts are auto-created on
first run:

| Username | Password | Role |
|---|---|---|
| `admin` | `AdminPass123` | Threat Administrator |
| `analyst1` | `AnalystPass123` | Security Analyst |
| `monitor1` | `MonitorPass123` | Monitoring Staff |

Run the automated test suite:
```bash
python test_auth.py
```

## How each assignment requirement is mapped to code

| Requirement | Where it lives |
|---|---|
| User registration | `auth/register.py` → `POST /api/auth/register` |
| Secure password hashing | `bcrypt.hashpw()` in `register.py` — passwords are never stored or returned in plain text |
| Login validation | `auth/login.py` → `POST /api/auth/login` |
| Session creation | `auth/session_manager.py` → `create_session()` issues a signed JWT |
| Session timeout | JWT `exp` claim, 30 minutes (`SESSION_TIMEOUT_MINUTES`) |
| Role-based authorization | `auth/role_manager.py` + `roles=[...]` on every route via `access_control.jwt_required` |
| Failed login tracking | `failed_attempts` counter per user in `login.py` |
| Account locking | 5 failed attempts → account locked 5 minutes (`MAX_FAILED_ATTEMPTS_PER_USER`) |
| Logout mechanism | `auth/logout.py` → `POST /api/auth/logout`, revokes the session server-side |
| Authentication logging | `auth/auth_logs.py` — every event in one timeline |
| JWT-protected threat APIs | All `/api/*` threat-intel routes use `@jwt_required(roles=[...])` |
| Multi-role access restrictions | admin / analyst / monitor each see different things (see table below) |
| Restrict incident/evidence access | `/api/incident/<id>` → `roles=["admin","analyst"]` only; monitor staff denied |
| Repeated failed analyst logins | Same account-locking logic applies to every role, including analysts |
| IP-based login restriction | `login.py` → `_register_failed_ip_attempt()`, blocks an IP for 10 min after 8 failed logins in 5 min |
| Session-expiry system | JWT `exp` + server-side `active_sessions` allow-list (logout invalidates instantly, not just on expiry) |
| Authentication timeline logs | `GET /api/auth/logs` (admin only) + visible live in the dashboard |
| Suspicious authentication detection | `login.py` flags 4+ distinct usernames attempted from one IP (credential-stuffing pattern) |
| Restrict blocked analysts | `POST /api/auth/users/<username>/lock` (admin) sets `disabled=True`, revokes all their sessions, login blocked |
| Audit trail for evidence access | every `/api/incident/<id>` call logs a `RESOURCE_ACCESS` entry with who/when |

## Role permissions at a glance

| Endpoint | admin | analyst | monitor |
|---|:---:|:---:|:---:|
| `/api/threat-summary` | ✅ | ✅ | ✅ |
| `/api/suspicious-ips` | ✅ | ✅ | ✅ |
| `/api/attack-logs` | ✅ | ✅ | ✅ |
| `/api/incident/<id>` (evidence) | ✅ | ✅ | ❌ |
| `/api/block-ip` | ✅ | ❌ | ❌ |
| `/api/auth/logs` (auth timeline) | ✅ | ❌ | ❌ |
| `/api/auth/users/*` (lock/unlock) | ✅ | ❌ | ❌ |

## API quick reference

### Register
```bash
curl -X POST http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"newanalyst","password":"SecurePass123","role":"analyst"}'
```

### Login (returns a JWT)
```bash
curl -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AdminPass123"}'
```

### Call a protected API
```bash
curl http://127.0.0.1:5000/api/threat-summary \
  -H "Authorization: Bearer <token from login response>"
```

### Logout
```bash
curl -X POST http://127.0.0.1:5000/api/auth/logout \
  -H "Authorization: Bearer <token>"
```

## Security notes for your report

- Passwords are hashed with **bcrypt** (includes its own per-password salt) —
  never stored or logged in plain text.
- JWTs are signed (HS256) and carry a short expiry; logout additionally
  revokes the session server-side so a token can't be reused after sign-out
  even though it technically hasn't expired yet.
- Account lockout (5 failed attempts) and IP-based blocking (8 failed logins
  across any username from one IP) defend against brute-force and
  credential-stuffing attacks respectively.
- `SECRET_KEY` values in `app.py` / `session_manager.py` are placeholders —
  in a real deployment these must come from environment variables, never be
  committed to source control.
