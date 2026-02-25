"""
alert_system.py — Simulates SOC alerting and automated incident response
Demonstrates SOAR-style automated actions based on threat severity.
"""

import json
import os
from datetime import datetime


class AlertSystem:
    """Simulated Security Operations Center (SOC) alert and response system."""

    # Response playbooks mapped to attack types
    PLAYBOOKS = {
        "BRUTE_FORCE": {
            "actions": [
                "Block source IP at firewall",
                "Lock targeted user account for 30 minutes",
                "Enable enhanced MFA for targeted account",
                "Notify SOC analyst via Slack #incidents",
            ],
            "priority": "HIGH",
        },
        "PORT_SCAN": {
            "actions": [
                "Block source IP at firewall",
                "Trigger full network scan from scanner IP range",
                "Log all connections from source IP for 24h",
                "Create investigation ticket",
            ],
            "priority": "MEDIUM",
        },
        "DDOS_FLOOD": {
            "actions": [
                "Enable rate limiting on affected service",
                "Activate DDoS mitigation (Cloudflare/AWS Shield)",
                "Block offending IP ranges at edge",
                "Page on-call network engineer",
                "Notify SOC analyst via Slack #incidents",
            ],
            "priority": "CRITICAL",
        },
        "PRIVILEGE_ESCALATION": {
            "actions": [
                "Immediately suspend affected user session",
                "Revoke all active tokens for user",
                "Capture forensic snapshot of host",
                "Escalate to Incident Response team",
                "Page CISO",
            ],
            "priority": "CRITICAL",
        },
        "SUSPICIOUS_ERRORS": {
            "actions": [
                "Log additional context for affected service",
                "Create low-priority investigation ticket",
            ],
            "priority": "LOW",
        },
        "UNKNOWN_ANOMALY": {
            "actions": [
                "Flag for manual review",
                "Collect additional log context (±15 min window)",
            ],
            "priority": "LOW",
        },
    }

    def __init__(self, alert_log_path="logs/alerts.json"):
        self.alert_log_path = alert_log_path
        self.alerts = []

    def process_anomaly_report(self, report):
        """
        Process each anomaly and generate alerts with automated response actions.

        Args:
            report: List of anomaly dicts from AnomalyDetector.get_anomaly_report()
        """
        print("\n" + "=" * 70)
        print("  SIEM ALERT SYSTEM — AUTOMATED INCIDENT RESPONSE")
        print("=" * 70)

        if not report:
            print("\n  [✓] No anomalies detected. All systems nominal.")
            return

        for anomaly in report:
            alert = self._create_alert(anomaly)
            self.alerts.append(alert)
            self._display_alert(alert)

        # Summary
        print("\n" + "-" * 70)
        print(f"  SUMMARY: {len(self.alerts)} alerts generated")
        severity_counts = {}
        for a in self.alerts:
            sev = a["priority"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev, count in sorted(severity_counts.items()):
            print(f"    {sev}: {count}")
        print("-" * 70)

        # Save alerts to JSON log
        self._save_alerts()

    def _create_alert(self, anomaly):
        """Create a structured alert from an anomaly entry."""
        attack_type = anomaly["attack_type"]
        playbook = self.PLAYBOOKS.get(attack_type, self.PLAYBOOKS["UNKNOWN_ANOMALY"])

        alert = {
            "alert_id": f"ALERT-{len(self.alerts) + 1:04d}",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "time_window": anomaly["time_window"],
            "attack_type": attack_type,
            "severity": anomaly["severity"],
            "priority": playbook["priority"],
            "anomaly_score": anomaly["anomaly_score"],
            "indicators": {
                "event_count": anomaly["event_count"],
                "error_ratio": anomaly["error_ratio"],
                "failed_logins": anomaly["failed_logins"],
                "unique_ips": anomaly["unique_ips"],
                "avg_bytes": anomaly["avg_bytes"],
            },
            "automated_actions": playbook["actions"],
        }
        return alert

    def _display_alert(self, alert):
        """Print a formatted alert to console."""
        priority_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }
        icon = priority_icons.get(alert["priority"], "⚪")

        print(f"\n  {icon} [{alert['alert_id']}] {alert['priority']} — {alert['attack_type']}")
        print(f"     Time Window : {alert['time_window']}")
        print(f"     Score       : {alert['anomaly_score']}")
        print(f"     Events      : {alert['indicators']['event_count']} | "
              f"Errors: {alert['indicators']['error_ratio']*100:.0f}% | "
              f"Failed Logins: {alert['indicators']['failed_logins']}")
        print(f"     Response Actions:")
        for action in alert["automated_actions"]:
            print(f"       → {action}")

    def _save_alerts(self):
        """Save all alerts to a JSON file."""
        os.makedirs(os.path.dirname(self.alert_log_path), exist_ok=True)
        with open(self.alert_log_path, "w") as f:
            json.dump(self.alerts, f, indent=2)
        print(f"\n  [+] Alerts saved to {self.alert_log_path}")
