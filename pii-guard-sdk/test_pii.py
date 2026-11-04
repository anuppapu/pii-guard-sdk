
import json
from pii_guard import PIIGuard, PolicyBlockedError

POLICY_PATH = "policies/default_pii_policy.json"
HASH_KEY = "0123456789abcdef0123456789abcdef"

guard = PIIGuard.from_json(
    POLICY_PATH,
    hash_key=HASH_KEY,
)


def test_text_sanitization():
    print("\n===== 1. TEXT SANITIZATION =====")

    text = """
    Employee: John Smith
    Email: john.smith@gmail.com
    Phone: +1 415-555-0198
    SSN: 123-45-6789
    Credit Card: 4532015112830366
    Employee ID: EMP123456
    Salary: $125,000
    DOB: 1990-05-15
    """

    result = guard.sanitize(text)

    print("Original text:")
    print(text)

    print("\nSanitized text:")
    print(result.sanitized_text)

    print("\nPII detected:", result.has_pii)
    print("Blocked:", result.blocked)

    print("\nAudit-safe findings:")
    print(json.dumps(result.safe_findings, indent=2))


def test_crm_record():
    print("\n===== 2. CRM RECORD SANITIZATION =====")

    crm_record = {
        "lead_id": "LEAD123456",
        "first_name": "John",
        "last_name": "Smith",
        "personal_email": "john.smith@gmail.com",
        "personal_phone": "+1 415-555-0198",
        "ssn": "123-45-6789",
        "date_of_birth": "1990-05-15",
        "bank_account": "123456789012",
        "credit_card": "4532015112830366",
        "address": {
            "home_address": "123 Main Street, New York",
            "postal_code": "10001",
        },
        "employment": {
            "salary": "$125,000",
            "department": "Technology",
        },
    }

    result = guard.sanitize_record(crm_record)

    print("Sanitized CRM record:")
    print(json.dumps(result.sanitized_record, indent=2))

    print("\nPII detected:", result.has_pii)
    print("Blocked:", result.blocked)

    print("\nAudit-safe findings:")
    print(json.dumps(result.safe_findings, indent=2))


def test_hmac_hashing():
    print("\n===== 3. HMAC HASHING =====")

    text = "Employee ID: EMP123456"

    result = guard.sanitize(text)

    print("Original:", text)
    print("Sanitized:", result.sanitized_text)

    print(
        "\nThe employee ID is replaced with a deterministic "
        "HMAC-SHA256 identifier."
    )


def test_blocking():
    print("\n===== 4. CREDENTIAL BLOCKING =====")

    text = """
    Username: john
    Password: MySecretPassword123
    API Key: abcdefghijklmnopqrstuvwxyz123456
    """

    result = guard.sanitize(text)

    print("Sanitized output:")
    print(result.sanitized_text)

    print("Blocked:", result.blocked)

    if result.blocked:
        print("WARNING: Sensitive credentials detected.")


def test_explicit_block_action():
    print("\n===== 5. EXPLICIT BLOCK ACTION =====")

    text = "Password: MySecretPassword123"

    try:
        result = guard.sanitize(text, action="block")

        if result.blocked:
            raise PolicyBlockedError(
                "Request blocked due to sensitive information."
            )

    except PolicyBlockedError as exc:
        print("Request rejected:", exc)


def test_masking():
    print("\n===== 6. MASKING =====")

    text = """
    Email: john.smith@gmail.com
    Phone: +1 415-555-0198
    Credit Card: 4532015112830366
    """

    result = guard.sanitize(text, action="mask")

    print("Original:")
    print(text)

    print("Masked:")
    print(result.sanitized_text)


if __name__ == "__main__":
    test_text_sanitization()
    test_crm_record()
    test_hmac_hashing()
    test_blocking()
    test_explicit_block_action()
    test_masking()

    print("\n===== ALL TESTS COMPLETED =====")
