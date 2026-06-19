"""Evidence agent: OSCAL packages + expiry management."""
from .guardrails import require_human_approval

class EvidenceAgent:
    def emit(self, findings, policies):
        oscal = {"system-security-plan": {}, "results": findings}
        require_human_approval("release OSCAL evidence")
        return oscal
