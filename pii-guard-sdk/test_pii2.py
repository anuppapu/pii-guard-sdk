
from pii_guard import PIIGuard

POLICY_PATH = "policies/default_pii_policy.json"
# This is a sample hash key for demonstration purposes. In a real application, you should use a secure and unique hash key.
# The key is used only when a finding’s action is hash: the sanitizer uses it to compute an HMAC-SHA256 digest of the matched value

HASH_KEY = "0123456789abcdef0123456789abcdef"

guard = PIIGuard.from_json(
    POLICY_PATH,
    hash_key=HASH_KEY,
)


def process_data(text: str) -> dict:
    # First scan the input
    scan_result = guard.scan(text)

    # Check whether any critical PII has a block action
    critical_blocked = any(
        finding.severity == "critical"
        and finding.strategy == "block"
        for finding in scan_result
    )

    # Sanitize all detected PII
    result = guard.sanitize(text)

    if critical_blocked:
        return {
            "blocked": True,
            "message": (
                "Your data has been blocked due to "
                "critical sensitive information available."
            ),
            "data": result.sanitized_text,
        }

    # No blocking critical PII found
    return {
        "blocked": False,
        "message": "No critical blocking PII detected. Data sanitized.",
        "data": result.sanitized_text,
    }


if __name__ == "__main__":

    sample_data = """
    Employee: John Smith
    Email: john.smith@gmail.com
    Phone: +1 415-555-0198
    SSN: 123-45-6789
    Password: MySecretPassword123
    API Key: abcdefghijklmnopqrstuvwxyz123456
    Employee ID: EMP123456
    Salary: $125,000
    """

    response = process_data(sample_data)

    print("Blocked:", response["blocked"])
    print("Message:", response["message"])
    print("\nProcessed Data:")
    print(response["data"])
