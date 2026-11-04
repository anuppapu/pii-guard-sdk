# PII Guard SDK

A lightweight Python SDK for detecting and protecting sensitive information before it is sent to an LLM, API, or another downstream system.

PII Guard loads a configurable JSON policy to identify sensitive text patterns and sensitive field names. Depending on the policy, findings can be allowed, masked, hashed, redacted, or blocked.

> **Important:** This tool is not a guarantee that all PII will be detected. Review and tune the policy for your data and use case. Do not send data onward when the result is blocked.

## Features

- Configurable regex detection using `policies/default_pii_policy.json`
- Sensitive-field rules for structured records
- Severity levels: `low`, `medium`, `high`, and `critical`
- Actions: `allow`, `mask`, `hash`, `redact`, and `block`
- HMAC-SHA256 one-way hashing
- Sanitization results with findings and blocked status
- Optional FastAPI backend and HTML demo UI

## Project structure

```text
pii-guard-sdk/
├── policies/
│   └── default_pii_policy.json
├── src/
│   └── pii_guard/
│       ├── __init__.py
│       ├── core.py
│       └── exceptions.py
├── app.py
├── sample_test.py
├── pii-guard-ui.html
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10 or later
- The SDK core uses only the Python standard library.
- FastAPI and Uvicorn are needed only for the optional demo API.

## Installation

Create and activate a virtual environment.

**Windows PowerShell**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux**
```bash
python -m venv .venv
source .venv/bin/activate
```

Install the SDK from the repository root:

```bash
python -m pip install --upgrade pip
pip install -e .
```

Install the optional API dependencies:

```bash
pip install -r requirements.txt
```

## Basic SDK usage

```python
from pii_guard import PIIGuard

guard = PIIGuard.from_json(
    "policies/default_pii_policy.json",
    hash_key="replace-with-a-secret-key-loaded-from-your-environment",
)

text = "Contact me at alex@example.com"
result = guard.sanitize(text)

print("Blocked:", result.blocked)
print("Sanitized text:", result.sanitized_text)

for finding in result.findings:
    print(finding.safe_summary())
```

For real deployments, load the HMAC key from a secret manager or environment variable. Do not hardcode it or commit it to source control.

## Run the FastAPI demo

If `app.py` is present, start the backend from the repository root:

```bash
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Open the API documentation at:

http://127.0.0.1:8000/docs

In a second terminal, change to the folder containing `pii-guard-ui.html` and run:

```bash
python -m http.server 5500
```

Open the UI at:

http://127.0.0.1:5500/pii-guard-ui.html

Configure the UI JavaScript to call the backend:

```javascript
const API_URL = "http://127.0.0.1:8000/api/process";
```

For local development, configure CORS in FastAPI to allow the UI origin. Before deployment, restrict CORS to trusted origins and add appropriate authentication and authorization.

## Blocking behavior

When a result is blocked, stop processing and do not forward the original or sanitized payload to an LLM or downstream service unless an explicitly designed review workflow permits it.

Be clear about the difference between policy action and severity. If the requirement is to block every critical-severity finding, implement that rule explicitly. If only selected critical patterns have the `block` action in the policy, only those patterns will trigger policy-based blocking.

## Hashing is not encryption

HMAC-SHA256 is a keyed, one-way hash. It is not reversible encryption and cannot be decrypted to recover the original value.

The SDK core does not implement authenticated encryption. If reversible encryption is required, use an approved cryptographic library or managed key service, with suitable key management and access controls.

## Security notes

- Use synthetic data in demos and tests.
- Never commit API keys, HMAC keys, passwords, private keys, access tokens, production records, or customer data.
- Keep `.env` files out of Git. Use `.env.example` only for variable names and placeholders.
- Restrict CORS and add authentication before exposing the API beyond localhost.
- Use HTTPS for network traffic outside local development.
- Review policy coverage, false positives, and false negatives before production use.
- Avoid logging raw PII; prefer safe summaries and carefully reviewed metadata.
- Apply appropriate access controls, retention limits, monitoring, and incident-response procedures.

## License

Add a license file before publishing if you want to grant others explicit reuse rights. Do not claim a license until one is included.
