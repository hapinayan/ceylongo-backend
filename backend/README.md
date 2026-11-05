# CeylonGo — Module 02: Phase 1 Authentication Foundation (SQL Server Integration Pending)

> **Deliverable Status:** Phase 1 authentication foundation; SQL Server integration pending.<br/>
> This deliverable establishes the core security interfaces, input validation, JWT issuance, rate limiting, and authorization dependencies. Live database login against Microsoft SQL Server 2022 will be attached in Phase 2 once Anushan confirms the physical schema. Live unconfigured requests safely return 503 Service Unavailable.

Shared backend service for the CeylonGo Tourism Platform powering the Angular Web Client (Tourists) and Flutter Mobile App (Vendors & Admins).

---

## 1. Module 02 Scope & Architecture Overview

Module 02 implements the core authentication and authorization layer for CeylonGo.

### Implemented Capabilities (Phase 1):
- **Endpoint:** `POST /api/auth/login` (JSON request: `email`, `password`).
- **Validation:** Pydantic v2 strict schema with RFC 5322 email syntax validation and `extra = "forbid"` (rejects client-supplied `role` fields).
- **Password Verification:** Replaceable `PasswordVerifierInterface` with provisional `BcryptPasswordVerifier` enforcing strict 72-byte input limits without silent truncation.
- **Timing Difference Reduction:** Pre-computed static dummy verification executed when an email address is not found in the database.
- **Option A Inactive Account Policy:** Returns the identical generic `401 Unauthorized` (`"Invalid email or password"`) for nonexistent emails, incorrect passwords, or inactive accounts.
- **JWT Access Tokens:** OAuth2 Bearer tokens signed with HS256 containing minimal claims (`sub`, `iat`, `exp`). Sensitive personal data, emails, and roles are excluded from token payloads.
- **Reusable Dependencies:**
  - `get_current_user`: Decodes bearer token and resolves the user in real time from the database.
  - `require_roles(["Admin", ...])`: Enforces role-based authorization returning `403 Forbidden` for unauthorized roles.
- **Rate Limiting:** In-memory, thread-safe, sliding-window rate limiter with memory-bounded capacity (defaults to 5 failed attempts per 60 seconds; returns 429 with `Retry-After`).
  - *Limitation:* Single Python process in-memory implementation. A distributed cache (e.g. Redis) is required for multi-worker scaling.
- **Angular CORS:** Restricted explicitly to `http://localhost:4200` and `http://127.0.0.1:4200` (`allow_credentials=False` for Bearer token flow).
- **Zero Mock Authentication in Production:** Default production wiring uses `UnconfiguredUserRepository`, which safely fails with a sanitized `503 Service Unavailable` until Phase 2 database integration is completed.

---

## 2. Windows Environment Setup Guide

### 2.1 Prerequisites
- **Python 3.11 or 3.12+**
- **PowerShell 5.1 or PowerShell 7+**

### 2.2 Create and Activate Virtual Environment
Open PowerShell in the project root directory:
```powershell
# Navigate to the backend directory
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment in PowerShell
.\.venv\Scripts\Activate.ps1
```

### 2.3 Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2.4 Configure Environment File
```powershell
# Copy the example environment template
Copy-Item .env.example .env
```
Generate a secure random 32-character key for `SECRET_KEY`:
```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```
Paste this value into `.env` under `SECRET_KEY`.

---

## 3. Running the Test Suite

The test suite contains 24 isolated unit tests covering API validation, credentials, Option A error policy, JWT encoding/decoding, CORS preflights, rate limiting, and password boundary checks.

Run all tests from the repository root:
```powershell
& "backend/.venv/Scripts/pytest.exe" -c backend/pytest.ini -o pythonpath=backend backend/tests -v
```
Or directly from inside `backend/`:
```powershell
cd backend
pytest -v
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
    "id": "usr-tourist-001",
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
   - `pip install -r requirements.txt` கட்டளையை இயக்கினால் FastAPI, Pydantic, PyJWT, Bcrypt மற்றும் Pytest நிறுவப்படும்.

3. **சோதனைகளை இயக்குதல் (Run Tests):**
   - அனைத்து 24 unit tests-களையும் சரிபார்க்க `pytest -v` கட்டளையை இயக்கவும்.

4. **FastAPI சேவையைத் தொடங்குதல் (Start Server):**
   - `uvicorn app.main:app --reload --port 8000` கட்டளையை இயக்கினால் backend தயாராகிவிடும்.
   - Swagger API ஆவணங்களை `http://127.0.0.1:8000/docs` இல் காணலாம்.
