# Automated Web Log Forensic & Threat Analyzer

A modular, high-throughput log forensic utility engineered in Python to parse web server access logs (Nginx/Apache), evaluate multi-vector threat signatures, detect authentication brute-force patterns, and export structured forensic telemetry.

---

## Technical Overview

Security Operations Centers (SOC) and Incident Response (IR) teams ingest and analyze access logs to detect post-exploitation traces, active reconnaissance, and malicious payload delivery.

This engine processes standard **Combined Log Format** streams, normalizes URL-encoded strings, evaluates behavioral anomalies against regex threat rules, and flags security incidents in real time.

---

## Threat Vectors Analyzed

- **SQL Injection (SQLi):** Detection of union queries, table destruction syntax, schema enumeration, and stacked SQL operators.
- **Cross-Site Scripting (XSS):** Recognition of script tags, injected event attributes (`onload`, `onerror`), and JavaScript URI schemes.
- **Directory Traversal / Local File Inclusion (LFI):** Detection of path transversal sequences (`../`, `..\`) and targeting of sensitive system objects (`/etc/passwd`, `win.ini`).
- **Automated Reconnaissance Scanners:** Identification of automated security scanners via client telemetry (e.g., `sqlmap`, `nikto`, `wpscan`, `gobuster`).
- **Brute Force & Credential Stuffing:** Frequency-based anomaly tracking identifying repeated authentication failures (`401`/`403`) against sensitive endpoints (`/login`, `/admin`).

---

## Architectural Workflow

```text
[Raw Access Log] ──> [LogParser (Regex & URL Unquote)]
                             │
                             ▼
                    [ThreatDetector Engine]
                      ├── Signature Match (SQLi, XSS, LFI, Scanners)
                      └── Frequency Tracker (Brute-Force Anomaly)
                             │
                             ▼
              [Diagnostic Console Output & JSON Report]

                         