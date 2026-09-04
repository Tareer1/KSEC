"""SOC alert pipeline (spec: SOC MODULE / SOC ALERT PIPELINE).

Event -> Normalize -> Enrich -> Correlate -> Rule Evaluation -> Risk Score
      -> Alert -> Case -> Investigation -> Resolution.

Events arrive from any source (firewall, IDS, endpoint, job output, manual),
are normalized into a canonical record, enriched with KSEC context (assets,
IOCs, findings), correlated against recent related events, evaluated against
deterministic detection rules, scored, and escalated into alerts that can
auto-open cases (spec 08#16-18, 05#48).
"""