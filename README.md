# redevops.io Agentic Compliance & Data-Privacy Monitoring

## Pain → Legacy → redevops.io

SMEs need SOC2/GDPR/HIPAA/PCI but Vanta/Drata cost $20K-$40K/yr with lock-in and the 2025 Vanta multi-tenant breach exposed customer data. redevops.io is self-hosted AGPL open-source.

## Headline Value Props

- Compliance Automation That Doesn't Own You
- SOC 2 for $10K Instead of $40K
- Full data-ownership/no-SaaS-breach risk
- 4 weeks not 12 months
- Open-source/no-lock-in

## What It Does

Four agents power continuous compliance:

- **Continuous Scanner** – automated discovery and monitoring of compliance posture
- **Policy-as-Code Manager** – codified, version-controlled policies
- **Automated Remediation** – safe, auditable fixes
- **Evidence Collector & Auditor Liaison** – automated evidence packaging and auditor hand-off

## Architecture

**OSS core**
- OpenSCAP / ComplianceAsCode for scanning
- Open Policy Agent (OPA) for policy evaluation
- OSCAL reporting
- STIX/TAXII threat intel integration
- Ansible remediation playbooks

**Agent layer** runs on top, orchestrating the OSS components with pattern recognition, evidence gathering, and enforcement actions.

## Honest Agent Boundaries

Agents perform pattern recognition, evidence collection, and enforcement. Humans retain all legal, strategic, and risk decisions.

## Quickstart

```bash
git clone https://github.com/redevops-io/agent-harness
cd agent-harness
cp .env.example .env
docker-compose up -d
```

See `.env.example` for required variables. Licensed AGPL-3.0.