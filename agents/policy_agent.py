"""Policy agent: translate requirements to OPA Rego."""
from .guardrails import require_human_approval

class PolicyAgent:
    def translate(self, findings):
        rego = "package compliance\n\ndefault allow = false"
        require_human_approval("publish Rego policy")
        return rego
