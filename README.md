# Agentic Security Operations Center (SOC) Assistant

An AI-powered cybersecurity analysis assistant designed to enable security operations center (SOC) analysts to query deception logs and binaries metadata using natural language. 

The application utilizes a FastAPI backend, a PostgreSQL relational database with JSONB indexing, JWT authentication, and a web-based dashboard interface. Security controls enforce a strict read-only database execution context for the LLM agent to prevent destructive queries.

---

## Technical Stack

- **Backend:** Python 3.11, FastAPI, Uvicorn
- **Database:** PostgreSQL (hybrid relational and JSONB schemas)
- **Language Model:** Groq API (Llama 3.1 8B/70B models)
- **Authentication:** JSON Web Tokens (JWT), PBKDF2 password hashing (HMAC-SHA256)
- **Frontend:** HTML5, CSS3, ES6 JavaScript

---

## Project Structure

```text
├── app/
│   ├── api/
│   │   ├── auth.py             # User signup and login routes
│   │   └── chat.py             # Authenticated chat execution route
│   ├── agents/
│   │   ├── orchestrator.py     # Multi-step execution & summary orchestrator
│   │   └── intent_classifier.py# Rule & LLM intent router
│   ├── tools/
│   │   ├── top_attackers.py    # Top attackers count query
│   │   ├── ip_investigation.py # Multi-source IP forensic analyzer
│   │   ├── protocol_summary.py # Global protocol event counter
│   │   ├── event_search.py     # Filter logs by specific criteria
│   │   └── binary_search.py    # Searches binaries analytics records
│   ├── database/
│   │   ├── client.py           # Connection clients for admin/agent roles
│   │   └── repositories.py     # Parameterized SQL database queries
│   ├── security/
│   │   └── authentication.py   # JWT signing and password hashing utilities
│   ├── static/                 # Static web dashboard assets
│   └── main.py                 # Core application initializer
├── scripts/
│   └── import_data.py          # Database setup and bulk JSON import tool
├── tests/                      # Automated unit and API test suites
├── requirements.txt            # Python dependencies
├── .env.example                # Sample configuration template
└── README.md                   # Repository documentation
```

---

## Security Model

1. **Read-Only Database Account:**
   The orchestrator queries the database using a restricted database account (`soc_agent`) with only `SELECT` privileges. Destructive operations (`DROP`, `DELETE`, `UPDATE`, `TRUNCATE`) are blocked by the database engine.
2. **SQL Injection Prevention:**
   The language model is not permitted to generate direct SQL queries. It is restricted to extracting structured parameters (such as `ip`, `limit`, `username`) which are validated and passed using parameterized SQL execution (`%s`).
3. **Prompt Injection Rejection:**
   Rule-based triggers inspect queries for destructive directives or override phrases. If identified, queries are rejected immediately without LLM processing.
4. **Secure Password Hashing:**
   User credentials are password-hashed using PBKDF2 (HMAC-SHA256) with 100,000 iterations and a cryptographically secure 16-byte salt.

---

## Database Design

The database uses PostgreSQL to combine relational search performance with unstructured document storage:
- **Relational Columns:** Attributes (`attacker_ip`, `username`, `timestamp`, `protocol`) are parsed during import, stored in dedicated columns, and indexed.
- **JSONB Column:** The full raw log is stored in a `data` column, ensuring schema flexibility.

---

## Setup & Setup Guide

### 1. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Configure Environment
Copy the environment template and insert your keys:
```bash
cp .env.example .env
```
Update the `GROQ_API_KEY` with a valid Groq completion API key.

### 3. Initialize Database and Import Data
Verify that your PostgreSQL service is running, then execute the setup and import script:
```bash
python3 scripts/import_data.py --data-dir ./data
```

### 4. Start the Application
Run the ASGI server:
```bash
python3 -m uvicorn app.main:app --reload
```
Access the dashboard at: **`http://localhost:8000`**

---

## Server Management (Lifecycle Control)

Execute these commands from the project root directory to manage background services:

### PostgreSQL Database
- **Start Database:**
  ```bash
  pg_ctl -D ./postgres_data -l ./postgres_data/server.log start
  ```
- **Stop Database:**
  ```bash
  pg_ctl -D ./postgres_data stop
  ```
- **Restart Database:**
  ```bash
  pg_ctl -D ./postgres_data -l ./postgres_data/server.log restart
  ```
- **Status Check:**
  ```bash
  pg_ctl -D ./postgres_data status
  ```

### FastAPI Application Server
- **Start Server:**
  ```bash
  python3.11 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
  ```
- **Stop Server:**
  Press `CTRL + C` in the active terminal window.

---

## Automated Verification

Execute the test suite using `pytest`:
```bash
python3 -m pytest tests/ -v
```
The test suite covers:
- JWT authentication and token verification.
- Duplicate user registration checks.
- Parameter validation for database tools.
- Multi-step forensic workflows.
- Rejection of prompt injection and destructive queries.
