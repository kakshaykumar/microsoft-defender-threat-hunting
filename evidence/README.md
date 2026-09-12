# Evidence index

Screenshots are numbered by the stage of work they document. Every file below is referenced from the main README or the incident report.

## 00 — Environment and baseline detections

| File | What it shows |
|---|---|
| `00-sense-running.png` | Defender for Endpoint sensor service confirmed running on the onboarded host |
| `00-av-status.png` | Real-time protection and antivirus both enabled |
| `00-device-onboarded.png` | Device appearing in the Defender device inventory |
| `00-alerts-both-sources.png` | Three baseline alerts from two detection sources — EDR for behaviour, Antivirus for content |

## 01 — Incident triage and classification

| File | What it shows |
|---|---|
| `01-incident-list.png` | Incident queue with priority score, severity and alert count |
| `01-alerts-list.png` | All three alerts after classification and resolution |
| `01-attack-story.png` | Incident graph and process ancestry — the interactive parent chain that drove the benign verdict |
| `01-deviceid-count.png` | Device identity confirmed as one DeviceId despite two name spellings in the portal |

## 02 — Device timeline

| File | What it shows |
|---|---|
| `02-timeline-discovery-systeminfo.png` | `systeminfo.exe` tagged T1082 plus five further techniques |
| `02-timeline-discovery-netlocalgroup.png` | `net.exe` handing off to `net1.exe`, tagged T1069.001 and T1087.001 |
| `02-timeline-file-events.png` | File events filter showing `archive.zip` and `page.html` recorded |
| `02-timeline-archivefile-events.png` | Archive creation alongside the `Compress-Archive` and `Remove-Item` commands |
| `02-timeline-file-not-found.png` | Timeline search for `file1.txt` returning no data — the telemetry gap |
| `02-timeline-network.png` | Network events filter with the PowerShell-initiated connection |
| `02-timeline-network-staging.png` | Data staging tagged T1005 plus six further techniques |
| `02-alert-queue-after.png` | Alert queue after the chain completed — nothing new fired |

## 03 — Single-table hunting queries

| File | What it shows |
|---|---|
| `03-kql-process-discovery.png` | `DeviceProcessEvents` filtered to PowerShell-spawned processes |
| `03-kql-file-events.png` | `DeviceFileEvents` returning two of five queried filenames |
| `03-kql-powershell-commands.png` | `DeviceEvents` with JSON command text unpacked via `parse_json` |
| `03-kql-network.png` | `DeviceNetworkEvents` filtered to PowerShell-initiated connections. Run over a 30-day window, so it returns the incident connection plus later unrelated PowerShell traffic including Defender's own telemetry uploads — a working example of how a wide hunting window returns noise that has to be reasoned about |

## 04 — Multi-table correlation

| File | What it shows |
|---|---|
| `04-kql-correlation.png` | The `union` query normalising four tables into one schema |
| `04-correlation-results.png` | Chronological timeline of the full activity chain across four tables |

## 05 — Detection engineering

| File | What it shows |
|---|---|
| `05-kql-detection-logic.png` | Detection query with two chained inner joins and time bounding |
| `05-detection-query-results.png` | Pre-deduplication result showing two rows for one incident |
| `05-detection-dedup-query.png` | Deduplicated to one row using `summarize arg_min()` |
| `05-detection-rule-created.png` | Rule deployed and enabled in the custom detection rules list |
| `05-detection-rule-summary.png` | Rule after scheduled execution, with its triggered alert |
| `05-detection-rule-actions.png` | Remediation actions deliberately left unconfigured |

---

Tenant identifiers, device IDs, account names and internal IP addresses are redacted throughout.
