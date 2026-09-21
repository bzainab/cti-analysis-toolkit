# Asset exposure review

Generated: 2026-09-21T12:05:24.619636+00:00
Intelligence collected: 2026-09-21T11:48:01.049546+00:00

## Decision summary
3 asset/CVE pairs reviewed; 2 meet the documented P1 threshold.
The inventory is an analyst-supplied assertion of affected software. Confirm versions, exposure and compensating controls before action. This report is not evidence of compromise.

## Findings
### P1 | DEMO-gateway | CVE-2024-3400
Score: 85/100; owner: Example network team; supplied CVSS: 10.0.
- CISA KEV confirms exploitation in the wild (+40)
- CISA reports ransomware use (+15)
- EPSS unknown; no likelihood points assigned
- Inventory asserts internet exposure (+15)
- Business criticality 5/5 (+15)
- Inventory CVSS 10.0/10; displayed separately from triage
Recommended action: Apply mitigations per vendor instructions as they become available. Otherwise, users with vulnerable versions of affected devices should enable Threat Prevention IDs available from the vendor. See the vendor bulletin for more details and a patch release schedule.
Reference: https://www.cve.org/CVERecord?id=CVE-2024-3400

### P1 | DEMO-file-transfer | CVE-2023-34362
Score: 82/100; owner: Example applications team; supplied CVSS: 9.8.
- CISA KEV confirms exploitation in the wild (+40)
- CISA reports ransomware use (+15)
- EPSS unknown; no likelihood points assigned
- Inventory asserts internet exposure (+15)
- Business criticality 4/5 (+12)
- Inventory CVSS 9.8/10; displayed separately from triage
Recommended action: Apply updates per vendor instructions.
Reference: https://www.cve.org/CVERecord?id=CVE-2023-34362

### P2 | DEMO-logging-service | CVE-2021-44228
Score: 67/100; owner: Example platform team; supplied CVSS: 10.0.
- CISA KEV confirms exploitation in the wild (+40)
- CISA reports ransomware use (+15)
- EPSS unknown; no likelihood points assigned
- Business criticality 4/5 (+12)
- Inventory CVSS 10.0/10; displayed separately from triage
Recommended action: For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.
Reference: https://www.cve.org/CVERecord?id=CVE-2021-44228

## Escalation and next steps
For confirmed high-priority exposure, notify the remediation owner and SOC with the affected asset, business impact, source evidence and validation status. Confirm patch status; review relevant telemetry and preserve evidence if suspicious activity is found.

## Confidence and limitations
High confidence in a match to the supplied KEV snapshot; asset exposure depends on the inventory’s accuracy. EPSS is a model estimate, not proof of exploitation. Scores are an explicit portfolio heuristic, not CVSS or an enterprise risk standard. Missing enrichment never means zero risk.
