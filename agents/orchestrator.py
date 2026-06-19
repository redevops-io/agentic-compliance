"""Multi-agent orchestrator and entrypoint."""
from .scanner_agent import ScannerAgent
from .policy_agent import PolicyAgent
from .remediation_agent import RemediationAgent
from .evidence_agent import EvidenceAgent

def run_pipeline():
    s = ScannerAgent()
    p = PolicyAgent()
    r = RemediationAgent()
    e = EvidenceAgent()
    findings = s.scan()
    policies = p.translate(findings)
    playbooks = r.generate(findings)
    e.emit(findings, policies)
    return {"findings": findings, "policies": policies, "playbooks": playbooks}
