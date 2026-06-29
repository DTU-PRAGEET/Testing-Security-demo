# SECURITY EVALUATION GUIDE — DVPWA (Ground-Truth Answer Key)

> **CONFIDENTIAL — EVALUATOR ONLY.**
> This document is the ground-truth answer key for benchmarking a multi-agent
> security remediation platform against the DVPWA repository. **It must never be
> placed inside the evaluation repository, indexed by the agents, or otherwise
> made reachable by the Research / Planner / Implementation agents.** Keep it
> outside the repo or in an ignored path that the agents cannot read.

---

## 0. How to use this guide

1. Strip the educational material from the evaluation copy of the repo (see
   **Section 1 — Dataset Hygiene**).
2. Run the Research Agent against the cleaned repo.
3. Compare the agent's findings against the per-vulnerability sections below.
4. Use the **Final Checklist** (Section 3) to score coverage, correctness of
   root cause, correctness of remediation, and ordering/dependency awareness.

DVPWA is an aiohttp (async Python) web app. Stack:

- **Web framework:** `aiohttp` + `aiohttp_jinja2` + `aiohttp_session`
- **DB:** PostgreSQL via `aiopg` (raw SQL in a hand-rolled DAO layer)
- **Session store:** Redis via `aiohttp_session.redis_storage.RedisStorage`
- **Templating:** Jinja2
- **Validation:** `trafaret`

---

## 1. Dataset Hygiene (cross-reference to Part 1)

The only file that *explicitly teaches* the vulnerabilities is **`README.rst`**.
Its "Vulnerabilities" section enumerates Session Fixation, SQL Injection, Stored
XSS, weak password storage (MD5), and CSRF — with reproduction steps,
mitigations, and even direct links to vulnerable line numbers. **Remove it (or at
minimum delete its "Vulnerabilities" section) from the evaluation copy.**

Residual structural hints that cannot be deleted without breaking the app
(document them as evaluation bias, do not treat as "discovery"):

- The Python package is named **`sqli`** (imports depend on it).
- Project title "Damn Vulnerable Python Web Application" / DB named `sqli`.

Everything else (all of `sqli/**.py`, `templates/**`, `migrations/**`,
`config/dev.yaml`, Docker/compose, `run.py`, `requirements.txt`) is genuine
application logic and **must remain** so the agent can reason over it.

---

## 2. Vulnerability Catalogue

Severity uses CVSS-style qualitative bands. "Discoverability" = how hard it is to
find by code analysis alone (after README removal).

---

### V1 — SQL Injection in Student creation

- **Challenge/Lesson name:** SQL Injection (the project's flagship lesson)
- **Category:** OWASP A03:2021 Injection / CWE-89 (SQL Injection)
- **Severity:** Critical
- **Discoverability:** Easy

**Short description**
The "Add new student" feature builds an `INSERT` statement by interpolating
user-controlled input directly into the SQL string, allowing arbitrary SQL
execution (data exfiltration, table drop, auth bypass on other queries, etc.).

**Root cause**
String formatting (`%`) is used to assemble the query instead of passing
parameters to the driver. Note the value is also wrapped in literal quotes,
making classic `'); ... --` breakouts trivial.

**Affected files / classes**
- `sqli/dao/student.py` → `Student.create()`

```42:45:sqli/dao/student.py
        q = ("INSERT INTO students (name) "
             "VALUES ('%(name)s')" % {'name': name})
        async with conn.cursor() as cur:
            await cur.execute(q)
```

**Entry points**
- `POST /students/` → `sqli/views.py::students` → `Student.create(conn, data['name'])`
- The `name` field comes straight from `request.post()` with **no validation**
  (note: `STUDENT_SCHEMA` exists in `sqli/schema/forms.py` but is never applied
  in the view).

**Impact if exploited**
Full read/write of the database. Canonical payload
`Robert'); DROP TABLE students CASCADE; --` destroys the `students` table.
Attackers can also dump `users.pwd_hash`, escalate, or pivot.

**Secure remediation strategy**
Use parameterized queries (driver binds the value, never string-format SQL).
Optionally also enforce `STUDENT_SCHEMA` in the view.

**Expected code change**
```python
@staticmethod
async def create(conn: Connection, name: str):
    q = "INSERT INTO students (name) VALUES (%(name)s)"
    async with conn.cursor() as cur:
        await cur.execute(q, {'name': name})
```
(Remove the literal single quotes; pass params as the second arg to `execute`.)

**Files to modify**
- `sqli/dao/student.py` (required)
- `sqli/views.py::students` (recommended: validate with `STUDENT_SCHEMA`)

**Validation / testing**
- Submit a student named `Robert'); DROP TABLE students CASCADE; --`; confirm a
  student row is created with that literal name and the table still exists.
- Submit `x'; SELECT ...` style payloads; confirm they're stored literally.
- Regression: normal names still insert and render.

**Side effects**
Self-contained. The `create()` signature is unchanged, so `views.py` callers
keep working. Adding schema validation changes error responses for empty names.

---

### V2 — Stored XSS in course reviews (global autoescape disabled)

- **Challenge/Lesson name:** Stored XSS
- **Category:** OWASP A03:2021 Injection (XSS) / CWE-79
- **Severity:** High
- **Discoverability:** Easy–Medium

**Short description**
Review text submitted by users is stored and later rendered into the course page
without escaping, so injected HTML/JS executes in other users' browsers (stored
/ persistent XSS).

**Root cause**
Two compounding defects:
1. Jinja2 is configured with `autoescape=False` globally.
2. The course template prints `review.review_text` with no `| e` filter.

**Affected files / classes**
- `sqli/app.py` → `setup_jinja(..., autoescape=False)`

```33:35:sqli/app.py
    setup_jinja(app, loader=PackageLoader('sqli', 'templates'),
                context_processors=[csrf_processor, auth_user_processor],
                autoescape=False)
```

- `sqli/templates/course.jinja2` → unescaped `{{ review.review_text }}`

```20:28:sqli/templates/course.jinja2
            {% for review in reviews %}
                <li class="collection-item">
                    {{ review.review_text }}
```

> Note: because autoescape is global, **many** template expressions are
> unescaped (`course.description`, `course.title`, `student.name` in
> `students.jinja2`, etc.). Some templates defensively apply `| e`, but the app
> is XSS-prone wherever `| e` is missing. The review flow is the documented
> path.

**Entry points**
- Store: `POST /courses/{course_id}/review` → `sqli/views.py::review` →
  `Review.create()`. The view checks only that `review_text` is non-empty; it
  does **not** apply `REVIEW_SCHEMA` or sanitize.
- Reflect/execute: `GET /courses/{id}` renders all reviews via `course.jinja2`.

**Impact if exploited**
Session/cookie theft (made worse by V6 — cookies are not HttpOnly), account
takeover, defacement, CSRF-chaining, drive-by actions as the victim.

**Secure remediation strategy**
Enable output escaping by default and rely on Jinja2 autoescaping; treat any
`| safe` as an explicit, audited exception. Optionally sanitize on input.

**Expected code change**
- In `sqli/app.py`: `autoescape=True` (preferred: `autoescape=select_autoescape(['html','xml','jinja2'])`).
- Remove any reliance on unescaped output; verify templates render correctly with
  escaping on. Remove now-redundant manual `| e` only if desired (harmless to keep).

**Files to modify**
- `sqli/app.py` (required — the single highest-leverage fix)
- `sqli/templates/course.jinja2` (defense in depth, optional once autoescape on)

**Validation / testing**
- Submit review `<b>bold?</b>` then `<script>alert(document.cookie)</script>`;
  after fix, the page shows the literal text, no bold, no alert.
- View page source: payload appears HTML-entity-encoded.
- Regression: legitimate text/punctuation still displays.

**Side effects**
Turning on autoescape is global and may double-encode content in templates that
already pipe through `| e` (cosmetic — `&amp;` style); review templates after
enabling. No data migration needed (fix is render-time).

---

### V3 — Weak password storage (unsalted MD5)

- **Challenge/Lesson name:** "Bad choice for storing passwords"
- **Category:** OWASP A02:2021 Cryptographic Failures / CWE-916, CWE-759 (no salt)
- **Severity:** High
- **Discoverability:** Easy

**Short description**
User passwords are stored as **unsalted MD5** hashes — fast, collision-prone, and
trivially reversible via rainbow tables; identical passwords yield identical
hashes (statistical leakage).

**Root cause**
`User.check_password` compares `md5(password)` against a stored MD5 hash, and the
fixtures seed `md5(...)` hashes directly.

**Affected files / classes**
- `sqli/dao/user.py` → `check_password()`

```40:41:sqli/dao/user.py
    def check_password(self, password: str):
        return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()
```

- `migrations/001-fixtures.sql` → `md5('superadmin')`, `md5('password')`, etc.

**Entry points**
- Login: `POST /` → `sqli/views.py::index` → `user.check_password(password)`.

**Impact if exploited**
If the DB is leaked (e.g., via V1), all passwords are recovered almost instantly,
enabling account takeover and lateral movement (password reuse).

**Secure remediation strategy**
Use a memory-hard / adaptive password hash (argon2id, bcrypt, or PBKDF2) with a
per-user salt. Store the full encoded hash (algorithm + salt + params + digest).
Verify with a constant-time comparison provided by the library.

**Expected code change**
- Add a dependency (e.g., `argon2-cffi` or `bcrypt`) to `requirements.txt`.
- Replace `check_password` with a verify call (e.g., `PasswordHasher().verify(...)`).
- Add a `set_password`/hash helper and update fixtures to store argon2/bcrypt
  hashes (or include a migration/seed that re-hashes).
- Schema note: `pwd_hash TEXT` already accommodates longer encoded hashes.

**Files to modify**
- `sqli/dao/user.py` (required)
- `requirements.txt` (required — new hashing lib)
- `migrations/001-fixtures.sql` (required — reseed with strong hashes)
- Any user-creation path if one is added later.

**Validation / testing**
- Seed a user with the new scheme; confirm login works and stored hash is
  argon2/bcrypt format (e.g., `$argon2id$...`).
- Confirm two users with the same password have **different** stored hashes.
- Confirm old MD5 login no longer validates (or implement transparent rehash on
  login if backward compatibility is desired).

**Side effects**
Requires reseeding/migrating existing hashes — old MD5 hashes won't verify under
the new scheme unless you add a fallback+rehash path. Touches login flow; test
end-to-end.

---

### V4 — Session Fixation (no session ID rotation on login)

- **Challenge/Lesson name:** Session fixation
- **Category:** OWASP A07:2021 Identification & Authentication Failures / CWE-384
- **Severity:** High
- **Discoverability:** Medium–Hard (behavioral; requires reasoning about session lifecycle)

**Short description**
The session identifier is not regenerated when a user authenticates. An attacker
who fixes a victim's session ID beforehand shares the authenticated session after
the victim logs in.

**Root cause**
On successful login the code sets `session['user_id']` on the **existing**
session without rotating/invalidating the session identifier. Logout likewise
only pops the key rather than destroying/rotating the session.

**Affected files / classes**
- `sqli/views.py::index` (login) — sets `session['user_id'] = user.id` with no rotation.

```41:43:sqli/views.py
        if user and user.check_password(password):
            session['user_id'] = user.id
            auth_user = user
```

- `sqli/views.py::logout` — `session.pop('user_id', None)` (no invalidation/rotation).
- Storage config: `sqli/middlewares.py::session_middleware` (`RedisStorage`).

**Entry points**
- `POST /` (login), `POST /logout/`.

**Impact if exploited**
Account takeover via a pre-seeded/known session ID (especially feasible because
cookies are not HttpOnly — see V6 — so XSS can plant a session value).

**Secure remediation strategy**
Rotate the session on every privilege change: invalidate the old session and
issue a fresh session ID on login and on logout. With `aiohttp_session`, create a
new session / change the identity rather than mutating the old one.

**Expected code change**
- On login success: obtain a new session (e.g., call the storage's
  new-session/`session.invalidate()` then set `user_id`, or use a helper that
  rotates the cookie's session token) so the pre-auth identifier can't be reused.
- On logout: `session.invalidate()` instead of just popping `user_id`.

**Files to modify**
- `sqli/views.py` (`index` login branch and `logout`) — required.
- Possibly `sqli/middlewares.py` / a small session helper if rotation needs
  storage-level support.

**Validation / testing**
- Capture pre-login `AIOHTTP_SESSION` cookie; log in; confirm the cookie value
  changed and the old value is no longer authenticated.
- Reproduce the README steps (two tabs, shared cookie) and confirm the incognito
  tab is **not** logged in after the fix.

**Side effects**
Rotation may clear other session data (e.g., `last_visited`, `_csrf_token`);
re-seed needed values after rotation. Interacts with V5 (CSRF token lives in the
session) — re-issue CSRF token post-rotation.

---

### V5 — CSRF protection disabled

- **Challenge/Lesson name:** Cross-site request forgery (README marks this "TBA")
- **Category:** OWASP A01:2021 Broken Access Control (CSRF) / CWE-352
- **Severity:** High
- **Discoverability:** Medium

**Short description**
State-changing POST endpoints are not CSRF-protected: a working CSRF middleware
exists but is **commented out**, so although forms embed a `_csrf_token`, nothing
verifies it.

**Root cause**
`csrf_middleware` is disabled in the middleware chain; the token is generated and
rendered but never validated server-side.

**Affected files / classes**
- `sqli/app.py` — CSRF middleware commented out.

```25:30:sqli/app.py
        middlewares=[
            session_middleware,
            # csrf_middleware,
            error_middleware,
        ]
```

- `sqli/middlewares.py::csrf_middleware` — implemented but unused.
- `sqli/utils/jinja2.py::csrf_processor` — provides `csrf_token()` to templates.

**Entry points**
All POST routes: `POST /` (login), `POST /students/`, `POST /courses/`,
`POST /courses/{id}/review`, `POST /students/{sid}/evaluate/{cid}`, `POST /logout/`.
Note `evaluate.jinja2`'s form does **not** even include a `_csrf_token` field.

**Impact if exploited**
Forged authenticated actions: create students/courses (SQLi via V1!), post
reviews (stored XSS via V2), evaluate students, or force logout — all without the
victim's consent.

**Secure remediation strategy**
Enable the CSRF middleware, ensure every state-changing form includes the token,
and use the existing per-session token comparison (consider constant-time compare
and rotating the token).

**Expected code change**
- Uncomment `csrf_middleware` in `sqli/app.py` (and import it).
- Add the missing `_csrf_token` hidden input to `evaluate` (form lives in
  `course.jinja2`'s aside and posts to `/students/{id}/evaluate/{cid}`).
- Optional: harden `csrf_middleware` token comparison with `hmac.compare_digest`.

**Files to modify**
- `sqli/app.py` (required)
- `sqli/templates/course.jinja2` (add token to the evaluate form) — required for the evaluate route
- `sqli/middlewares.py` (optional hardening)

**Validation / testing**
- Submit a POST without/with a wrong `_csrf_token`; expect `403 Forbidden`.
- Submit with the correct token from the rendered form; expect success.
- Verify every POST form (login, students, courses, review, evaluate, logout)
  carries a valid token.

**Side effects**
Any client/automation that posts without a token will break. Interacts with V4:
token is session-bound, so re-issue it after session rotation. Enabling CSRF
turns the SQLi/XSS routes from "victim-must-act" into properly gated actions.

---

### V6 — Session cookie not HttpOnly (and not Secure)

- **Challenge/Lesson name:** (Not separately documented; supporting weakness)
- **Category:** OWASP A05:2021 Security Misconfiguration / CWE-1004 (Sensitive Cookie Without HttpOnly), CWE-614 (no Secure flag)
- **Severity:** Medium (High in combination with V2)
- **Discoverability:** Medium

**Short description**
The session cookie is created with `httponly=False`, so client-side JavaScript can
read the session token; the Secure flag is likewise not set.

**Root cause**
`RedisStorage` is instantiated with `httponly=False`.

**Affected files / classes**
- `sqli/middlewares.py::session_middleware`

```19:22:sqli/middlewares.py
    app = request.app
    storage = RedisStorage(app['redis'], httponly=False)
    middleware = session_middleware_(storage)
    return await middleware(request, handler)
```

**Entry points**
Every request (the session middleware runs globally).

**Impact if exploited**
Directly amplifies V2 (Stored XSS): `document.cookie` exposes the session,
enabling theft/fixation (ties to V4).

**Secure remediation strategy**
Set `httponly=True`, and `secure=True` (when served over HTTPS), plus a sensible
`samesite` attribute (`Lax` or `Strict`).

**Expected code change**
```python
storage = RedisStorage(app['redis'], httponly=True, secure=True, samesite='Lax')
```
(Use `secure=True` only behind TLS; keep `httponly=True` unconditionally.)

**Files to modify**
- `sqli/middlewares.py` (required)

**Validation / testing**
- Inspect `Set-Cookie`; confirm `HttpOnly` (and `Secure`/`SameSite`) present.
- Confirm `document.cookie` no longer exposes the session token.
- Regression: login/session still works.

**Side effects**
`secure=True` over plain HTTP (the default docker setup is HTTP on :8080) will
prevent the cookie from being set — gate it on TLS/config. Minimal otherwise.

---

### V7 — Broken Access Control / Missing function-level authorization

- **Challenge/Lesson name:** (Not separately documented; real defect)
- **Category:** OWASP A01:2021 Broken Access Control / CWE-862 (Missing Authorization), CWE-285
- **Severity:** High
- **Discoverability:** Medium–Hard

**Short description**
Authorization is enforced only in templates (admin-only forms are hidden in the
UI), but the server-side handlers do not check authentication/role. Anyone can
call the state-changing endpoints directly.

**Root cause**
An `authorize(ensure_admin=...)` decorator exists in `sqli/utils/auth.py` but is
applied **only** to `logout`. The privileged handlers (`students` POST, `courses`
POST, `evaluate`) have no auth/role guard; templates merely use
`{% if auth_user.is_admin %}` to hide controls (client-side enforcement only).

**Affected files / classes**
- `sqli/views.py` — `students`, `courses`, `evaluate` lack `@authorize(...)`.
- `sqli/utils/auth.py` — `authorize` decorator (only used on `logout`).
- Templates `courses.jinja2`, `course.jinja2` (aside) hide forms by role but do
  not enforce.

```51:60:sqli/views.py
@template('students.jinja2')
async def students(request: Request):
    app: Application = request.app
    if request.method == 'POST':
        data = await request.post()
        async with app['db'].acquire() as conn:
            await Student.create(conn, data['name'])
```

**Entry points**
- `POST /students/` (create student — also the SQLi sink, V1)
- `POST /courses/` (create course — admin-only in UI)
- `POST /students/{sid}/evaluate/{cid}` (assign marks — admin-only in UI; no auth at all)

**Impact if exploited**
Unauthenticated/non-admin users can create courses, add students (triggering V1),
and assign grades — full bypass of the intended admin boundary.

**Secure remediation strategy**
Enforce authorization server-side on every privileged handler with the existing
decorator: `@authorize()` for authenticated-only and `@authorize(ensure_admin=True)`
for admin-only actions. Keep template gating as UX only.

**Expected code change**
- Decorate `courses` (POST) and `evaluate` with `@authorize(ensure_admin=True)`.
- Decorate `students` (POST path) appropriately (at least `@authorize()`; admin if
  intended). Because `index`/`students`/`courses` serve both GET and POST in one
  handler, you may need to split GET vs POST or check `request.method`/role inside.

**Files to modify**
- `sqli/views.py` (required)
- Possibly `sqli/utils/auth.py` (if you add a POST-only or method-aware guard)

**Validation / testing**
- As anonymous/non-admin, POST directly to `/courses/`, `/students/`, and
  `/students/1/evaluate/1`; expect `401/403`.
- As admin, confirm the same actions succeed.
- Confirm GET pages still render for the appropriate roles.

**Side effects**
Combined handlers (GET+POST) mean a blanket decorator could also block public GET
pages — implement method/role-aware checks to avoid breaking read access. Closing
this reduces the attack surface for V1/V2 (the sinks become admin-gated).

---

### V8 — Debug mode enabled / verbose errors (information disclosure)

- **Challenge/Lesson name:** (Not separately documented; misconfiguration)
- **Category:** OWASP A05:2021 Security Misconfiguration / CWE-489, CWE-209
- **Severity:** Low–Medium
- **Discoverability:** Easy

**Short description**
The application runs with `debug=True` and `logging.DEBUG`, which can leak stack
traces and internal details, aiding other attacks.

**Root cause**
`Application(debug=True, ...)` in `sqli/app.py` and `logging.basicConfig(level=logging.DEBUG)` in `run.py`.

**Affected files / classes**
- `sqli/app.py` (`debug=True`), `run.py` (`logging.DEBUG`).

**Entry points**
Global / any error path.

**Impact if exploited**
Leaks implementation details, file paths, and query errors (e.g., the SQLi error
message that confirms table names), accelerating exploitation.

**Secure remediation strategy**
Drive debug/log level from configuration; default to `False`/`INFO` in non-dev.

**Files to modify**
- `sqli/app.py`, `run.py` (and optionally `config/dev.yaml` / schema to add a flag).

**Validation / testing**
- Trigger a server error; confirm no stack trace/internal detail is returned to
  the client in production mode.

**Side effects**
Lower verbosity may hide useful dev info; gate behind config/env.

---

### V9 — Hardcoded / weak credentials and secrets in config

- **Challenge/Lesson name:** (Not separately documented; supporting weakness)
- **Category:** OWASP A05:2021 Security Misconfiguration / CWE-798 (Hardcoded Credentials), CWE-521 (Weak Password Requirements)
- **Severity:** Low–Medium (context dependent)
- **Discoverability:** Easy

**Short description**
Default/weak credentials are committed: DB `postgres/postgres` in
`config/dev.yaml`, and seed users with weak, guessable passwords (`superadmin/superadmin`, `password`).

**Root cause**
Secrets/credentials are stored in plaintext config and fixtures rather than
injected via environment/secret management; passwords don't meet any strength
policy.

**Affected files / classes**
- `config/dev.yaml`, `migrations/001-fixtures.sql`.

**Entry points**
Login (`POST /`), DB connection (`sqli/services/db.py`).

**Impact if exploited**
Trivial credential guessing / default-creds access; secret sprawl in VCS.

**Secure remediation strategy**
Source secrets from environment variables / secret store; remove defaults from
VCS; enforce password strength for seeded/real accounts.

**Files to modify**
- `config/dev.yaml`, `sqli/services/db.py` (read from env), `migrations/001-fixtures.sql`.

**Validation / testing**
- Confirm the app reads credentials from env/secret store and starts without
  committed secrets; confirm weak default accounts are removed/changed.

**Side effects**
Changing DB creds requires updating docker-compose/Postgres init. Low coupling to
the core challenges; treat as hardening.

---

## 3. Final Checklist (scoring sheet)

| # | Vulnerability | Category (CWE) | Primary file(s) | Expected fix (one-liner) | Difficulty | Documented in README? |
|---|---------------|----------------|-----------------|--------------------------|------------|------------------------|
| V1 | SQL Injection (student create) | CWE-89 | `sqli/dao/student.py` | Parameterize the `INSERT` | Easy | Yes |
| V2 | Stored XSS (reviews) | CWE-79 | `sqli/app.py`, `templates/course.jinja2` | `autoescape=True` (+ escape output) | Easy–Medium | Yes |
| V3 | Weak password hashing (MD5) | CWE-916/759 | `sqli/dao/user.py`, `migrations/001-fixtures.sql` | Use argon2/bcrypt + salt | Easy (find) / Medium (fix) | Yes |
| V4 | Session fixation | CWE-384 | `sqli/views.py`, `sqli/middlewares.py` | Rotate session on login/logout | Medium–Hard | Yes |
| V5 | CSRF disabled | CWE-352 | `sqli/app.py`, `sqli/middlewares.py`, `templates/course.jinja2` | Enable CSRF middleware + tokens | Medium | Yes (TBA) |
| V6 | Cookie not HttpOnly/Secure | CWE-1004/614 | `sqli/middlewares.py` | `httponly=True`, `secure`, `samesite` | Medium | No |
| V7 | Broken access control | CWE-862/285 | `sqli/views.py`, `sqli/utils/auth.py` | Apply `@authorize`/`ensure_admin` server-side | Medium–Hard | No |
| V8 | Debug mode / verbose errors | CWE-489/209 | `sqli/app.py`, `run.py` | Config-driven debug=False | Low | No |
| V9 | Hardcoded/weak credentials | CWE-798/521 | `config/dev.yaml`, `migrations/001-fixtures.sql` | Env-based secrets, strong creds | Low | No |

**Core "intended" challenges** (the ones the project was built to teach):
V1, V2, V3, V4, V5. **V6–V9** are real, additional weaknesses a strong Research
Agent should also surface and are good signal for grading depth.

### Recommended solve order

1. **V1 — SQL Injection** (critical, isolated, fastest win; also the headline lesson).
2. **V2 — Stored XSS** (single high-leverage flag: `autoescape=True`).
3. **V6 — Cookie HttpOnly/Secure** (cheap; meaningfully reduces V2 impact).
4. **V3 — Weak password hashing** (self-contained but needs a dep + reseed).
5. **V5 — CSRF** (do before/with V4 since the token lives in the session).
6. **V4 — Session fixation** (rotation must re-issue the CSRF token, hence after V5).
7. **V7 — Broken access control** (server-side authz; benefits from sessions being sound).
8. **V8 — Debug/verbose errors** and **V9 — secrets/creds** (hardening cleanup last).

### Dependencies between challenges

- **V2 ↔ V6:** XSS severity depends on cookie exposure; fixing V6 reduces V2 impact but does not fix V2.
- **V4 ↔ V5:** Session rotation (V4) clears the CSRF token (V5); the CSRF token is session-stored, so fix/verify them together and re-issue the token after rotation.
- **V4 ↔ V6:** HttpOnly (V6) and session rotation (V4) jointly mitigate fixation/theft.
- **V1/V2 ↔ V7:** The SQLi sink (`/students/` POST) and XSS store (`/courses/{id}/review`) are reachable partly due to missing authorization (V7) and missing CSRF (V5); tightening V5/V7 shrinks their exploitability even before the sinks are fixed.
- **V3 ↔ V1:** V1 is the realistic exfiltration path that makes V3 (offline cracking) catastrophic — useful to note when grading "impact" reasoning.

### Grading guidance

- **Coverage:** Did the agent find all five core flags (V1–V5)? Bonus for V6–V9.
- **Root cause:** Did it name the exact sink/line (e.g., string-formatted SQL,
  `autoescape=False`, MD5, no session rotation, commented-out CSRF middleware)?
- **Remediation correctness:** Does the proposed fix match the "Expected code
  change" and not merely mask symptoms (e.g., blacklisting `'` instead of
  parameterizing)?
- **Side-effect awareness:** Did it flag the V4↔V5 token coupling, the
  autoescape double-encode risk, the `secure`-over-HTTP pitfall, and the
  combined GET+POST handler issue for V7?
