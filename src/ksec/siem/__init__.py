"""SIEM auto-ingestion (spec: real SOC intake).

KSEC's SOC pipeline normally receives events one at a time via ``soc ingest``.
This package adds real-world intake: a UDP syslog-style listener and a
file/folder watcher that parse common log formats and push every record
through the same normalize -> enrich -> correlate -> alert -> case pipeline.
"""
