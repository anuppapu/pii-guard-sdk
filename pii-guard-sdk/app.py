
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pii_guard import PIIGuard

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

guard = PIIGuard.from_json(
    "policies/default_pii_policy.json",
    hash_key="0123456789abcdef0123456789abcdef",
)


class ScanRequest(BaseModel):
    text: str


@app.post("/api/process")
def process_data(request: ScanRequest):
    findings = guard.scan(request.text)

    critical_blocked = any(
        f.severity == "critical" and f.strategy == "block"
        for f in findings
    )

    result = guard.sanitize(request.text)

    return {
        "blocked": critical_blocked,
        "message": (
            "Your data has been blocked due to critical "
            "sensitive information available."
            if critical_blocked
            else "Data sanitized successfully."
        ),
        "data": result.sanitized_text,
        "findings": list(result.safe_findings),
    }
