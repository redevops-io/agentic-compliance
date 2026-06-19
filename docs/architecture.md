# Architecture

## Three-Layer Design

### 1. Redevops.io Agent Layer
- Scanner Agent
- Policy Agent
- Remediation Agent
- Evidence Agent
- Orchestrator

### 2. Open-Source Stack
- OpenSCAP / ComplianceAsCode
- Open Policy Agent (OPA)
- OSCAL reporting
- STIX/TAXII threat intel
- Ansible remediation

### 3. Self-Hosted Infrastructure
- Customer infra
- Evidence vault
- Audit reports

## Data Flow
Agents orchestrate the open-source components on customer infrastructure, storing evidence in the vault and producing audit reports.

## Honest Agent-Boundary Principle
Agents coordinate and invoke tools; they never execute privileged actions themselves. All remediation and scanning runs via customer-controlled Ansible, OpenSCAP, OPA, etc.