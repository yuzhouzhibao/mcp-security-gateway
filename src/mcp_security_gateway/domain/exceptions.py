class DomainError(ValueError):
    """Base error for invalid domain state."""


class InvalidStatusTransitionError(DomainError):
    """Raised when a requested status transition is not allowed by the caller."""
