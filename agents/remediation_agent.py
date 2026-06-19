"""Remediation agent: generate Ansible from ComplianceAsCode, human gate."""
from .guardrails import require_human_approval

class RemediationAgent:
    def generate(self, findings):
        playbook = [{"name": "remediate", "hosts": "all", "tasks": []}]
        require_human_approval("apply Ansible remediation")
        return playbook
