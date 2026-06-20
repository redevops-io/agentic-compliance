"""Evidence agent: OSCAL packages + expiry management."""
from .guardrails import require_human_approval

class EvidenceAgent:
    def emit(self, findings, policies, approved: bool = False):
        require_human_approval("release OSCAL evidence", approved=approved)
        oscal = {"system-security-plan": {}, "results": findings}
        return oscal
