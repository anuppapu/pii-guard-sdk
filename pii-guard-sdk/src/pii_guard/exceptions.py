class PIIGuardError(Exception):
    """Base exception for this package."""


class PolicyValidationError(PIIGuardError):
    """Raised when a JSON policy is invalid or unsafe to load."""


class InputTooLargeError(PIIGuardError):
    """Raised when input exceeds the configured scanning limit."""


class PolicyBlockedError(PIIGuardError):
    """Raised when one or more findings use the block action."""
