# CeylonGo — Module 02: Shared Login API (SQL Server Integration Verified)

> **Deliverable Status:** SQL Server Integration Verified; Client Integration Ready.<br/>
> This deliverable completes the end-to-end verified authentication service for CeylonGo. Live login, Argon2id password verification, database integer ID mappings, dynamic role querying, JWT access token issuance, and role authorization dependencies have been verified against Microsoft SQL Server 2022. All 43 unit tests and 10 isolated SQL Server integration tests pass.

Shared backend service for the CeylonGo Tourism Platform powering the Angular Web Client (Tourists) and Flutter Mobile App (Vendors & Admins).

---

## 1. Module 02 Scope & Architecture Overview

Module 02 implements the core authentication and authorization layer for CeylonGo.

### Implemented Capabilities (Phases 1 & 2):
- **Endpoint:** `POST /api/auth/login` (JSON request: `email`, `password`).
- **Validation:** Pydantic v2 strict schema with RFC 5322 email syntax validation and `extra = "forbid"` (rejects client-supplied `role` fields).
- **Password Verification:** Team-standardized `PasswordVerifierInterface` backed by `Argon2PasswordVerifier` using `pwdlib[argon2]` (`PasswordHash.recommended()`). Standardized on Argon2id (v=19, m=65536 KiB [64 MiB], t=3 iterations, p=4 lanes). Eliminates legacy bcrypt 72-byte restriction; full passwords preserved and verified exactly. Exported reusable `hash_password` helper for registration module integration.
- **Timing Difference Reduction:** Pre-computed static dummy verification executed when an email address is not found in the database.
- **Option A Inactive Account Policy:** Returns the identical generic `401 Unauthorized` (`"Invalid email or password"`) for nonexistent emails, incorrect passwords, or inactive accounts.
- **JWT Access Tokens:** OAuth2 Bearer tokens signed with HS256 containing minimal claims (`sub`, `iat`, `exp`). `sub` stores `str(user.id)`. Emails and roles are excluded from token payloads.
- **Repository Integration (`SqlAlchemyUserRepository`):**
  - Parameterized raw SQL queries matching `dbo.Users`, `dbo.UserRoles`, and `dbo.Roles`.
  - Maps database `INT IDENTITY` to domain integer `id`.
  - Preserves missing `RoleName` as `None` (never `str(None)`).
  - Offloaded to worker threads via `run_in_threadpool` to avoid blocking FastAPI's async event loop.
  - Safe session management via context manager closing each session cleanly.
- **Reusable Dependencies:**
  - `get_current_user`: Decodes bearer token, safely parses integer `sub` (returns 401 on malformed non-integer subject, never 500), and resolves the user and current role from the database. Rejects missing (`None`) or unknown roles immediately with safe 401.
  - `require_roles(["Admin", ...])`: Enforces role-based authorization returning `403 Forbidden` for unauthorized roles.
- **Rate Limiting:** In-memory, thread-safe, sliding-window rate limiter with memory-bounded capacity (defaults to 5 failed attempts per 60 seconds; returns 429 with `Retry-After`).
  - *Limitation:* Single Python process in-memory implementation. A distributed cache (e.g. Redis) is required for multi-worker scaling.
- **Angular CORS:** Restricted explicitly to `http://localhost:4200` and `http://127.0.0.1:4200` (`allow_credentials=False` for Bearer token flow).
- **Safe Fallback Wiring:** When `DATABASE_URL` is omitted, the application uses `UnconfiguredUserRepository`, which safely fails with a sanitized `503 Service Unavailable`.

### Scope Boundaries & Remaining Limitations:
- **In-Memory Rate Limiting:** Single Python process in-memory implementation. A distributed cache (e.g. Redis) is required for multi-worker scaling.
- **Registration & Profile Onboarding:** User registration, vendor verification/onboarding, and password reset endpoints belong to other FYP modules and are out of scope for Module 02.
- **TLS Certificate Validation:** `TrustServerCertificate=yes` is strictly for local development without custom CA certificates; production cloud environments must validate server certificates via proper CA chains.

---

## 2. Windows Environment Setup Guide

### 2.1 Prerequisites
- **Python 3.11 or 3.12+**
- **PowerShell 5.1 or PowerShell 7+**
- **Microsoft ODBC Driver 18 for SQL Server** (x64 Windows installer)
- **Microsoft SQL Server 2022** (Standard, Developer, Express, or LocalDB)

### 2.2 Accessing the Database Schema Script
The database teammate's schema script resides on remote branch `feature/mithushika-login`. To inspect or extract it without switching branches or merging:
```powershell
# Fetch the remote branch (read-only)
git fetch origin feature/mithushika-login

# Inspect the schema script directly
git show origin/feature/mithushika-login:database/CeylonGo_Login_Schema.sql
```

### 2.3 Create and Activate Virtual Environment
Open PowerShell in the project root directory:
```powershell
# Navigate to the backend directory
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment in PowerShell
.\.venv\Scripts\Activate.ps1
```

### 2.4 Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2.5 Configure Environment File
```powershell
# Copy the example environment template
Copy-Item .env.example .env
```
Generate a secure random 32-character key for `SECRET_KEY`:
```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```
Paste this value into `.env` under `SECRET_KEY`.

### 2.6 Database Connection Configuration
In `backend/.env`, configure `DATABASE_URL` matching your local SQL Server instance:

- **Option A: SQL Server Authentication (TCP Port 1433)**
  ```env
  DATABASE_URL="mssql+pyodbc://sa:YourPassword123@localhost:1433/CeylonGoDB?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
  ```
- **Option B: Named Instance (e.g. SQLEXPRESS) with Windows Authentication**
  ```env
  DATABASE_URL="mssql+pyodbc://@localhost\SQLEXPRESS/CeylonGoDB?driver=ODBC+Driver+18+for+SQL+Server&trusted_connection=yes&TrustServerCertificate=yes"
  ```
- **Option C: LocalDB with Windows Authentication**
  ```env
  DATABASE_URL="mssql+pyodbc://@(localdb)\MSSQLLocalDB/CeylonGoDB?driver=ODBC+Driver+18+for+SQL+Server&trusted_connection=yes&TrustServerCertificate=yes"
  ```

> [!NOTE]
> `TrustServerCertificate=yes` is strictly for local development without custom CA certificates; production environments must validate server certificates using proper CA chains.
> If `DATABASE_URL` is omitted, the application starts in safe fallback mode (returning 503 for login requests).

---

## 3. Running the Test Suite

The test suite contains 43 isolated unit tests and 10 isolated SQL Server integration tests.

### 3.1 Running Unit Tests (Default)
Unit tests run using in-memory mock repository interfaces and do not require SQL Server:
```powershell
& "backend/.venv/Scripts/pytest.exe" -c backend/pytest.ini -o pythonpath=backend backend/tests/unit -v
```
Or directly from inside `backend/`:
```powershell
cd backend
pytest tests/unit -v
```
When running the full test suite without integration opt-in, integration tests are automatically **SKIPPED** (reporting 43 passed, 10 skipped).

### 3.2 Running SQL Server Integration Tests (Isolated Test Database)
Integration tests verify live SQL Server queries, Argon2id verification, and authorization against `CeylonGoDB_LoginTest`. For multi-layer safety:
1. They require explicit opt-in via `RUN_SQL_SERVER_INTEGRATION_TESTS=1`.
2. They require an isolated `TEST_DATABASE_URL` (pointing to `CeylonGoDB_LoginTest`).
3. They strictly reject targeting the primary application `DATABASE_URL` or `CeylonGoDB`.
4. They create temporary test users, resolve role IDs dynamically, verify login and token access, and clean up all test records on fixture teardown.

To execute the integration tests:
```powershell
$env:RUN_SQL_SERVER_INTEGRATION_TESTS="1"
$env:TEST_DATABASE_URL="mssql+pyodbc://@.\SQLEXPRESS01/CeylonGoDB_LoginTest?driver=ODBC+Driver+18+for+SQL+Server&trusted_connection=yes&TrustServerCertificate=yes"
& "backend/.venv/Scripts/pytest.exe" -c backend/pytest.ini -o pythonpath=backend backend/tests/integration -v
```

---

## 4. Starting the FastAPI Server

To run the server locally:
```powershell
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- **API Base URL:** `http://127.0.0.1:8000`
- **Swagger UI Documentation:** `http://127.0.0.1:8000/docs` (available when `DEBUG=True`)
- **Health Check Endpoint:** `http://127.0.0.1:8000/api/health`

---

## 5. API Specification: `POST /api/auth/login`

### Request Headers
```http
Content-Type: application/json
```

### Request Body
```json
{
  "email": "tourist@example.com",
  "password": "TouristPass123!"
}
```

### Success Response (`200 OK`)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": 1,
    "name": "Nimal Perera",
    "email": "tourist@example.com",
    "role": "Tourist"
  }
}
```

### Error Responses
- **401 Unauthorized (Invalid credentials or inactive account):**
  ```json
  {
    "detail": "Invalid email or password"
  }
  ```
- **422 Unprocessable Entity (Validation error, password omitted from output):**
  ```json
  {
    "detail": [
      {
        "type": "value_error",
        "loc": ["body", "email"],
        "msg": "value is not a valid email address"
      }
    ]
  }
  ```
- **429 Too Many Requests (Rate limit exceeded):**
  ```json
  {
    "detail": "Too many login attempts. Please try again in 58 seconds."
  }
  ```
  *Headers:* `Retry-After: 58`
- **503 Service Unavailable (Database not yet configured):**
  ```json
  {
    "detail": "Database service is not configured or currently unavailable. Live login is not yet available."
  }
  ```

---

## 6. Client Integration Examples

### PowerShell / Windows Terminal Example
```powershell
$headers = @{
    "Content-Type" = "application/json"
}
$body = @{
    email    = "tourist@example.com"
    password = "TouristPass123!"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/auth/login" -Method Post -Headers $headers -Body $body
```

### cURL Example
```bash
curl -X POST "http://127.0.0.1:8000/api/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"email":"tourist@example.com","password":"TouristPass123!"}'
```

### Protected Request Using Token
```bash
curl -X GET "http://127.0.0.1:8000/api/protected-route" \
     -H "Authorization: Bearer <access_token>"
```

---

## 7. Angular Integration Guide (`AuthService`)

1. Make an HTTP POST call from `frontend/src/app/core/services/auth.service.ts`:
   ```typescript
   login(credentials: { email: string; password: string }): Observable<TokenResponse> {
     return this.http.post<TokenResponse>('http://127.0.0.1:8000/api/auth/login', credentials).pipe(
       tap(res => {
         localStorage.setItem('ceylongo_token', res.access_token);
         this.setUser(res.user);
       })
     );
   }
   ```
2. Attach the token in subsequent HTTP requests via an Angular HTTP interceptor:
   ```typescript
   headers: { Authorization: `Bearer ${token}` }
   ```

---

## 8. Simple Tamil Explanation (முக்கியமான படிகள்)

1. **மெய்நிகர் சூழலை (Virtual Environment) உருவாக்குதல்:**
   - PowerShell இல் `cd backend` செய்து `python -m venv .venv` கட்டளையை இயக்கவும்.
   - பிறகு `.\.venv\Scripts\Activate.ps1` மூலம் அதனை இயக்கவும் (Activate).

2. **தேவையான தொகுப்புகளை (Dependencies) நிறுவுதல்:**
   - `pip install -r requirements.txt` கட்டளையை இயக்கினால் FastAPI, Pydantic, PyJWT, pwdlib[argon2], SQLAlchemy, PyODBC மற்றும் Pytest நிறுவப்படும்.

3. **சோதனைகளை இயக்குதல் (Run Tests):**
   - 43 unit tests-களையும் சரிபார்க்க `pytest tests/unit -v` கட்டளையை இயக்கவும்.
   - SQL Server integration tests (10 tests) இயக்க `RUN_SQL_SERVER_INTEGRATION_TESTS=1` அமைத்து `pytest tests/integration -v` இயக்கலாம்.

4. **FastAPI சேவையைத் தொடங்குதல் (Start Server):**
   - `uvicorn app.main:app --reload --port 8000` கட்டளையை இயக்கினால் backend தயாராகிவிடும்.
   - Swagger API ஆவணங்களை `http://127.0.0.1:8000/docs` இல் காணலாம்.
   - SQL Server `.\SQLEXPRESS01` (`CeylonGoDB`) இணைக்கப்பட்டு Login API முழுமையாக Angular Tourist Client (`localhost:4200`) மற்றும் Flutter Apps உடன் இணையத் தயாராக உள்ளது.
