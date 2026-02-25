"""
anomaly_detector.py — Detects anomalous time windows using Isolation Forest
Scores each time window and classifies as NORMAL or ANOMALY.
Also provides severity ranking based on anomaly score.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class SIEMAnomalyDetector:
    """Isolation Forest-based anomaly detector for SIEM log features."""

    def __init__(self, contamination=0.08, random_state=42):
        """
        Args:
            contamination: Expected proportion of anomalies (0.0 to 0.5)
            random_state: Seed for reproducibility
        """
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=200,   # more trees = better detection
            max_samples="auto",
        )
        self.scaler = StandardScaler()
        self.feature_columns = None

    def fit_predict(self, feature_df):
        """
        Train the model and predict anomalies.

        Args:
            feature_df: DataFrame from feature_engine.extract_features()

        Returns:
            DataFrame with added columns: anomaly_score, is_anomaly, severity
        """
        self.feature_columns = feature_df.columns.tolist()
        X = feature_df.values

        # Normalize features so no single feature dominates
        X_scaled = self.scaler.fit_transform(X)

        # Fit and predict
        labels = self.model.fit_predict(X_scaled)   # +1 = normal, -1 = anomaly
        scores = self.model.decision_function(X_scaled)  # lower = more anomalous

        # Build results DataFrame
        results = feature_df.copy()
        results["anomaly_score"] = scores
        results["is_anomaly"] = (labels == -1).astype(int)

        # Assign severity: LOW / MEDIUM / HIGH / CRITICAL based on score percentile
        results["severity"] = results["anomaly_score"].apply(self._score_to_severity)

        n_anomalies = results["is_anomaly"].sum()
        print(f"[+] Detection complete: {n_anomalies} anomalous windows found "
              f"out of {len(results)} total")

        return results

    def _score_to_severity(self, score):
        """Map anomaly score to severity level."""
        if score > 0:
            return "NORMAL"
        elif score > -0.1:
            return "LOW"
        elif score > -0.2:
            return "MEDIUM"
        elif score > -0.3:
            return "HIGH"
        else:
            return "CRITICAL"

    def get_anomaly_report(self, results):
        """
        Generate a summary report of detected anomalies.

        Args:
            results: DataFrame from fit_predict()

        Returns:
            List of dicts describing each anomaly
        """
        anomalies = results[results["is_anomaly"] == 1].sort_values("anomaly_score")
        report = []

        for idx, row in anomalies.iterrows():
            # Determine likely attack type from features
            attack_type = self._classify_attack(row)

            entry = {
                "time_window": str(idx),
                "severity": row["severity"],
                "anomaly_score": round(row["anomaly_score"], 4),
                "attack_type": attack_type,
                "event_count": int(row["event_count"]),
                "error_ratio": round(row["error_ratio"], 2),
                "failed_logins": int(row["failed_logins"]),
                "unique_ips": int(row["unique_ips"]),
                "avg_bytes": round(row["avg_bytes"], 0),
            }
            report.append(entry)

        return report

    def _classify_attack(self, row):
        """Heuristic attack classification based on feature patterns."""
        if row["failed_logins"] > 10:
            return "BRUTE_FORCE"
        elif row["unique_services"] >= 5 and row["event_count"] > 15:
            return "PORT_SCAN"
        elif row["avg_bytes"] > 8000 and row["event_count"] > 20:
            return "DDOS_FLOOD"
        elif row["error_ratio"] > 0.5 and row["event_count"] < 10:
            return "PRIVILEGE_ESCALATION"
        elif row["error_ratio"] > 0.3:
            return "SUSPICIOUS_ERRORS"
        else:
            return "UNKNOWN_ANOMALY"


if __name__ == "__main__":
    from feature_engine import extract_features

    features = extract_features("logs/security_logs.csv")
    detector = SIEMAnomalyDetector(contamination=0.08)
    results = detector.fit_predict(features)

    report = detector.get_anomaly_report(results)
    print("\n=== ANOMALY REPORT ===")
    for entry in report:
        print(f"\n  [{entry['severity']}] {entry['time_window']}")
        print(f"    Attack Type : {entry['attack_type']}")
        print(f"    Score       : {entry['anomaly_score']}")
        print(f"    Events      : {entry['event_count']}")
        print(f"    Failed Login: {entry['failed_logins']}")
