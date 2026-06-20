"""Guardrails: human-in-the-loop gates, no legal/strategic decisions."""
import os


class PendingApprovalError(Exception):
    """Raised when a sensitive action proceeds without human approval."""


def require_human_approval(action: str, approved: bool = False) -> bool:
    """Enforce a human-in-the-loop gate for sensitive actions.

    Approval is required by default. It is granted only when an explicit
    ``approved=True`` token is passed by the caller, or the
    ``COMPLIANCE_HUMAN_APPROVED`` environment flag is truthy. When approval
    is withheld, this raises ``PendingApprovalError`` so callers cannot
    proceed with the sensitive action.
    """
    env_approved = os.getenv("COMPLIANCE_HUMAN_APPROVED", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if approved or env_approved:
        return True
    raise PendingApprovalError(f"Human approval required for: {action}")
