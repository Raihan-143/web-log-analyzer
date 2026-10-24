"""
core/detector.py
Threat signature evaluator and anomaly detection engine.
"""

import re
from typing import Dict, Any, List
from collections import defaultdict


class ThreatDetector:
    # Signatures for Common Web Attack Vectors
    THREAT_RULES = {
        "SQL Injection (SQLi)": re.compile(
            r"(\b(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table)\b|"
            r"'\s*or\s*'?1'?='?1|--|\bwaitfor\s+delay\b|\binformation_schema\b)",
            re.IGNORECASE
        ),
        "Cross-Site Scripting (XSS)": re.compile(
            r"(<script.*?>|javascript:|onload=|onerror=|<svg/onload=|<img\s+src=.*onerror=)",
            re.IGNORECASE
        ),
        "Directory Traversal / LFI": re.compile(
            r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/|win\.ini|boot\.ini)",
            re.IGNORECASE
        ),
        "Reconnaissance Scanner": re.compile(
            r"(sqlmap|nikto|nmap|masscan|wpscan|acunetix|nessus|gobuster|dirbuster)",
            re.IGNORECASE
        )
    }

    def __init__(self, brute_force_threshold: int = 5) -> None:
        self.brute_force_threshold = brute_force_threshold
        self.endpoint_failures = defaultdict(lambda: defaultdict(int))

    def evaluate_entry(self, entry: Dict[str, Any]) -> List[Dict[str, str]]:
        """Evaluates a log entry against threat rules."""
        findings = []
        target_payload = f"{entry['decoded_url']} {entry['user_agent']}"

        for attack_type, pattern in self.THREAT_RULES.items():
            if pattern.search(target_payload):
                findings.append({
                    "attack_type": attack_type,
                    "target_ip": entry["ip"],
                    "timestamp": entry["timestamp"],
                    "url": entry["url"],
                    "status": str(entry["status"]),
                    "user_agent": entry["user_agent"]
                })

        # Track authentication failures for brute force detection
        if entry["status"] in (401, 403) and any(login_kw in entry["url"].lower() for login_kw in ["login", "admin", "auth"]):
            self.endpoint_failures[entry["ip"]][entry["url"]] += 1

        return findings

    def get_brute_force_alerts(self) -> List[Dict[str, Any]]:
        """Flags IPs that exceeded the authentication failure threshold."""
        alerts = []
        for ip, endpoints in self.endpoint_failures.items():
            for endpoint, count in endpoints.items():
                if count >= self.brute_force_threshold:
                    alerts.append({
                        "attack_type": "Brute Force / Credential Stuffing",
                        "target_ip": ip,
                        "endpoint": endpoint,
                        "failure_count": count
                    })
        return alerts