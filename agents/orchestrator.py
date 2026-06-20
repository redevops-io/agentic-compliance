"""Multi-agent orchestrator and entrypoint."""
from .scanner_agent import ScannerAgent
from .policy_agent import PolicyAgent
from .remediation_agent import RemediationAgent
from .evidence_agent import EvidenceAgent

def run_pipeline(approved: bool = False):
    s = ScannerAgent()
    p = PolicyAgent()
    r = RemediationAgent()
    e = EvidenceAgent()
    findings = s.scan(approved=approved)
    policies = p.translate(findings, approved=approved)
    playbooks = r.generate(findings, approved=approved)
    e.emit(findings, policies, approved=approved)
    return {"findings": findings, "policies": policies, "playbooks": playbooks}
