# Intelligence review and hunt handoff

## Requirement
Which public reports could affect a supplied technology inventory, and what evidence would change the assessment? Define the audience, decision, source window and deadline before collection.

## Separate observations from conclusions
KEV inclusion is a source observation of exploitation in the wild. An inventory row is an assertion of local applicability. EPSS is a model estimate. A documented ATT&CK relationship is historical behaviour, not attribution for a new incident.

## Competing hypotheses exercise
Scenario: an analyst receives a report of an exposed product alongside an unexpected process alert. This is a fictional tabletop exercise.

| Evidence to seek | H1 Exploitation | H2 Authorised maintenance | H3 Scanner artefact |
|---|---|---|---|
| Confirmed vulnerable version and exposed endpoint | Consistent, insufficient alone | Neutral | Neutral |
| Verified maintenance ticket matching time and commands | Weakens | Supports | Weakens |
| Process lineage and network event corroboration | Supports if anomalous | Depends on ticket | Weakens if independently corroborated |
| Alert without raw telemetry | Unresolved | Unresolved | Consistent, insufficient alone |

Do not sum this table into a probability. Seek evidence that could disconfirm the leading explanation, document source reliability and gaps, and revise the assessment. ACH is a reasoning aid, not a substitute for investigation.

## Hunt handoff template
1. Requirement and hypothesis, including what would disconfirm it.
2. Source links and collection timestamps.
3. Affected assets and version evidence, with assumptions flagged.
4. Observed behaviour mapped to a sourced ATT&CK technique where justified.
5. Relevant telemetry: endpoint process lineage, authentication, application and network logs.
6. Time window, expected benign explanations and escalation owner.
7. Recommended containment only after validation and authorised incident procedures.

Cyber Kill Chain can organise a narrative from initial access through actions on objectives, but it does not by itself prove a sequence or supply missing evidence. Use ATT&CK technique IDs only when supported by observed behaviour or cited reporting.
