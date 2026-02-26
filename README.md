# IDOR (Insecure Direct Object Reference) - Security Research Project

## Overview

This project demonstrates the **IDOR (Insecure Direct Object Reference)** vulnerability in web applications. It includes a vulnerable web application, an automated exploit script, and a fixed (secure) version of the application.

> **Disclaimer**: This project is for **educational purposes only**. Do not use these techniques against systems without explicit authorization.

## Project Structure

```
idor-poc/
├── vulnerable-app/          # Intentionally vulnerable Flask application
│   └── app.py               # SecureShop - vulnerable web app
├── exploit/                  # Automated exploit scripts
│   └── idor_exploit.py       # IDOR exploitation script
├── fixed-app/                # Secure version with IDOR mitigations
│   └── app_secure.py         # SecureShop - fixed version
├── diagrams/                 # Visual diagrams
│   ├── attack_flow.mmd       # Attack flow (Mermaid source)
│   ├── attack_flow.png       # Attack flow diagram
│   ├── defense_comparison.mmd # Defense diagram (Mermaid source)
│   └── defense_comparison.png # Defense comparison diagram
├── final_project_report.md   # Complete project report (Hebrew)
└── README.md                 # This file
```

## Quick Start

### 1. Start the Vulnerable Application

```bash
cd vulnerable-app
python3 app.py
# Server starts on http://localhost:5000
```

### 2. Run the Exploit

```bash
cd exploit
python3 idor_exploit.py
```

### 3. Start the Secure Application

```bash
cd fixed-app
python3 app_secure.py
# Server starts on http://localhost:5001
```

## Vulnerabilities Demonstrated

| # | Type | Endpoint | Impact |
|---|------|----------|--------|
| 1 | Horizontal IDOR | `GET /api/user/{id}` | Profile data exposure |
| 2 | Horizontal IDOR | `GET /api/orders/{user_id}` | Order & payment data theft |
| 3 | Horizontal IDOR | `GET /api/messages/{id}` | Private message reading |
| 4 | Object-Level IDOR | `PUT /api/user/{id}` | Profile modification / Account takeover |
| 5 | Object-Level IDOR | `DELETE /api/orders/{id}` | Data destruction |

## Defense Mechanisms Implemented

1. **Object-Level Authorization** - Centralized decorator verifying resource ownership
2. **UUID-based References** - Unpredictable identifiers instead of sequential IDs
3. **Session-Based Access** - Resources accessed via server-side session, not client input
4. **Access Control Logging** - All unauthorized attempts are logged for monitoring

## Requirements

- Python 3.8+
- Flask
- requests (for exploit script)

## License

This project is for educational purposes only.
