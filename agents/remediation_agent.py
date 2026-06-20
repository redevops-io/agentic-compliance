"""Remediation agent: generate Ansible from ComplianceAsCode, human gate."""
from .guardrails import require_human_approval

class RemediationAgent:
    def generate(self, findings, approved: bool = False):
        require_human_approval("apply Ansible remediation", approved=approved)
        playbook = [{"name": "remediate", "hosts": "all", "tasks": []}]
        return playbook
