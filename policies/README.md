# Policies Directory

This directory contains the Policy-as-Code and OSCAL reporting artifacts consumed by the Policy-as-Code Manager and Evidence Collection agents.

## Contents
- `*.rego`: OPA Rego policies for SOC 2, HIPAA, GDPR, and PCI DSS. Each uses realistic control mappings (e.g., AC-2, 164.312, Art32, Req 3.4) and deny rules that produce violation messages.
- `oscal/component-definition.json`: OSCAL 1.1.2 component definition template ready for auditor export, referencing ComplianceAsCode control sources.

## Usage
Agents load Rego packages via `opa eval` or the OPA Go API and evaluate input documents (evidence JSON). Violations surface as `deny` set members. The OSCAL JSON is emitted as-is or enriched by the Evidence agent for downstream OpenSCAP/ComplianceAsCode tooling.