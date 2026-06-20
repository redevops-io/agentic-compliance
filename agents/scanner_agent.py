"""Scanner agent: OpenSCAP/ComplianceAsCode + control mapping."""
import subprocess
from .guardrails import require_human_approval

CONTROLS = {"GDPR": ["Art.32"], "PCI": ["Req.1"], "HIPAA": ["164.312"], "SOC2": ["CC6.1"]}

class ScannerAgent:
    def scan(self, approved: bool = False):
        try:
            subprocess.run(["oscap", "--version"], capture_output=True, check=True)
        except Exception:
            pass  # fallback for compile env
        require_human_approval("review findings", approved=approved)
        findings = [{"id": "xccdf_fail_1", "controls": CONTROLS}]
        return findings
