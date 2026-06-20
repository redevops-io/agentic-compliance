"""Policy agent: translate requirements to OPA Rego."""
from .guardrails import require_human_approval

class PolicyAgent:
    def translate(self, findings, approved: bool = False):
        require_human_approval("publish Rego policy", approved=approved)
        rego = "package compliance\n\ndefault allow = false"
        return rego
