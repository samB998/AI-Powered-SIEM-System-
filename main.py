#!/usr/bin/env python3
"""
main.py — AI-Powered SIEM System
=================================
A proof-of-concept Security Information and Event Management system
that uses machine learning (Isolation Forest) for anomaly detection
in security logs.

Pipeline:
  1. Generate synthetic security logs (or ingest real ones)
  2. Extract security-relevant features per time window
  3. Detect anomalies using Isolation Forest
  4. Classify attack types and generate alerts
  5. Simulate automated incident response (SOAR)
  6. Produce a visual security dashboard

Author: [Your Name]
Usage:  python main.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_generator import generate_logs
from feature_engine import extract_features
from anomaly_detector import SIEMAnomalyDetector
from alert_system import AlertSystem
from visualizer import generate_dashboard


def main():
    print("=" * 70)
    print("  AI-POWERED SIEM SYSTEM — Log Analysis & Anomaly Detection")
    print("=" * 70)

    # ---------------------------------------------------------------
    # STEP 1: Generate (or ingest) security logs
    # ---------------------------------------------------------------
    print("\n[STEP 1] Generating synthetic security logs...")
    log_path = generate_logs(
        output_path="logs/security_logs.csv",
        num_normal=500,
        seed=42,
    )

    # ---------------------------------------------------------------
    # STEP 2: Extract features from logs
    # ---------------------------------------------------------------
    print("\n[STEP 2] Extracting security features (5-min windows)...")
    feature_df = extract_features(log_path, window="5min")
    print(f"\n  Feature matrix shape: {feature_df.shape}")
    print(f"  Time range: {feature_df.index.min()} → {feature_df.index.max()}")

    # ---------------------------------------------------------------
    # STEP 3: Run anomaly detection (Isolation Forest)
    # ---------------------------------------------------------------
    print("\n[STEP 3] Running Isolation Forest anomaly detection...")
    detector = SIEMAnomalyDetector(contamination=0.08)
    results = detector.fit_predict(feature_df)

    # ---------------------------------------------------------------
    # STEP 4: Generate anomaly report
    # ---------------------------------------------------------------
    print("\n[STEP 4] Generating anomaly report...")
    report = detector.get_anomaly_report(results)

    if report:
        print(f"\n  Detected {len(report)} anomalous time windows:")
        for entry in report:
            print(f"    [{entry['severity']:>8}] {entry['time_window']} "
                  f"— {entry['attack_type']} (score: {entry['anomaly_score']})")
    else:
        print("  No anomalies detected.")

    # ---------------------------------------------------------------
    # STEP 5: Trigger automated alerts and response
    # ---------------------------------------------------------------
    print("\n[STEP 5] Processing alerts and automated response...")
    alert_sys = AlertSystem(alert_log_path="logs/alerts.json")
    alert_sys.process_anomaly_report(report)

    # ---------------------------------------------------------------
    # STEP 6: Generate security dashboard
    # ---------------------------------------------------------------
    print("\n[STEP 6] Generating security dashboard...")
    dashboard_path = generate_dashboard(feature_df, results, output_path="output/siem_dashboard.png")

    # ---------------------------------------------------------------
    # DONE
    # ---------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  PIPELINE COMPLETE")
    print("=" * 70)
    print(f"\n  Outputs:")
    print(f"    Logs         : logs/security_logs.csv")
    print(f"    Alerts       : logs/alerts.json")
    print(f"    Dashboard    : {dashboard_path}")
    print(f"\n  Next steps:")
    print(f"    - Try with real log data (replace log_generator with your logs)")
    print(f"    - Tune contamination parameter for your environment")
    print(f"    - Add more features (geo-IP, user agent, session duration)")
    print(f"    - Integrate with Slack/email for real alerting")
    print(f"    - Deploy as a Flask/Streamlit web dashboard")
    print()


if __name__ == "__main__":
    main()
