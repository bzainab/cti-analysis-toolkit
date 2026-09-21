# CTI Analysis Toolkit

Small, standard-library Python tools for turning public threat data into an explainable analyst work product. Built as a companion to [SignalDesk](https://github.com/bzainab/signaldesk-threat-intelligence).

## What it does

- Collects CISA KEV, FIRST EPSS and MITRE ATT&CK with source URLs and timestamps.
- Correlates explicit asset/CVE inventory rows with KEV, exposure and business criticality.
- Produces a prioritised JSON queue and a concise Markdown briefing with evidence, uncertainty and escalation steps.
- Exports an ATT&CK Navigator layer for a named group using documented direct relationships.
- Normalises defanged indicators and exports STIX 2.1 indicator bundles without contacting indicator destinations.

## Run it

Python 3.11 or newer. No third-party packages or API keys are required.

```sh
python collect.py --output data/intelligence.json
python analyze.py triage --intel data/intelligence.json --inventory examples/inventory.csv --out reports
python analyze.py layer --intel data/intelligence.json --group FIN7 --out layer.json
python analyze.py indicators --input examples/indicators.txt --out indicators.stix.json
python -m unittest discover -s tests -v
```

The example inventory is **synthetic**. Its asset names, owners and exposure are demonstrations, not a real organisation’s systems. CVSS values are illustrative analyst inputs, not a live CVSS feed. Indicator examples use reserved documentation addresses/domains and are not malicious.

## Scoring model

| Evidence | Points |
|---|---:|
| KEV match | 40 |
| Known ransomware use | 15 |
| EPSS | rounded probability × 15 |
| Asserted internet exposure | 15 |
| Criticality from 1 to 5 | criticality × 3 |

P1 is 70 or more; P2 is 45–69; P3 is below 45. CVSS is validated and displayed separately. This transparent heuristic supports review; it is not a calibrated enterprise risk model. Missing EPSS receives no model points and is explicitly labelled unknown. A non-KEV vulnerability may still be urgent.

Inventory columns are `asset,cve,internet_exposed,criticality,cvss,owner`. Each row asserts that the CVE applies. The tool does not infer vulnerable versions, scan infrastructure or discover exposure. Duplicate asset/CVE pairs are removed.

## Research method

Start with an intelligence requirement: which reported vulnerabilities warrant review against the supplied inventory? Record sources, separate source facts from asset assumptions, assess gaps, and communicate the recommended validation step. The sample report shows an operational handoff; [the research playbook](docs/research-playbook.md) provides a competing-hypotheses exercise and a hunt handoff template.

## Data and limitations

[CISA KEV](https://github.com/cisagov/kev-data) confirms observed exploitation. [FIRST EPSS](https://www.first.org/epss/data) predicts exploitation over the next 30 days. Only the latest 240 KEV entries receive EPSS enrichment to keep collection bounded. [MITRE ATT&CK STIX](https://github.com/mitre-attack/attack-stix-data) documents historical behaviours and citations. Its dataset and FIRST data retain their respective licences; see their source repositories and data pages.

Collection fails if KEV or ATT&CK is unavailable, preserving any previous output by writing atomically only after success. EPSS failures are recorded and scores remain unknown. No commercial intelligence, private telemetry or production SOC access is implied. STIX indicators preserve user assertions; export does not establish maliciousness.
