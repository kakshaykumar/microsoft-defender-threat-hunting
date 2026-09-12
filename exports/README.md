# Exports

Query results as CSV, exported directly from Advanced hunting.

| File | Source query | Rows | What it contains |
|---|---|---|---|
| `correlation-timeline.csv` | `hunting/06-correlation-timeline.kql` | 10 | The full activity chain across process, file, network and command telemetry, in chronological order |
| `detection-rule-match.csv` | `detections/powershell-discovery-archive-egress.kql` | 1 | The single deduplicated match produced by the detection logic, with the alert columns Defender requires |

`detection-rule-match.csv` has been redacted: `DeviceId` and `AccountName` are replaced with placeholders. `correlation-timeline.csv` required no redaction — it contains no identifiers, only timestamps, event types and command text.
