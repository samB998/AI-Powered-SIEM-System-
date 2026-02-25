"""
feature_engine.py — Extracts security-relevant features from raw logs
Features per time window (5-minute bins):
  - event_count: total events in window
  - error_ratio: proportion of ERROR/CRITICAL events
  - unique_ips: number of distinct source IPs
  - unique_services: number of distinct services accessed
  - failed_logins: count of failed login attempts
  - avg_bytes: average bytes transferred
  - ip_entropy: Shannon entropy of IP distribution (high = scan/DDoS)
"""

import pandas as pd
import numpy as np


def compute_entropy(series):
    """Compute Shannon entropy of a categorical series."""
    probs = series.value_counts(normalize=True)
    return -np.sum(probs * np.log2(probs + 1e-10))


def extract_features(log_path, window="5min"):
    """
    Read logs and compute features per time window.

    Args:
        log_path: Path to the CSV log file
        window: Time window for aggregation (default 5 minutes)

    Returns:
        DataFrame with one row per time window and computed features
    """
    df = pd.read_csv(log_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.set_index("timestamp", inplace=True)

    # Flag severity levels
    df["is_error"] = df["level"].isin(["ERROR", "CRITICAL"]).astype(int)
    df["is_failed_login"] = df["message"].str.contains("Failed login", case=False).astype(int)

    features = []

    for window_start, group in df.resample(window):
        if len(group) == 0:
            continue

        feat = {
            "window_start": window_start,
            "event_count": len(group),
            "error_ratio": group["is_error"].mean(),
            "unique_ips": group["src_ip"].nunique(),
            "unique_services": group["service"].nunique(),
            "failed_logins": group["is_failed_login"].sum(),
            "avg_bytes": group["bytes"].mean(),
            "max_bytes": group["bytes"].max(),
            "ip_entropy": compute_entropy(group["src_ip"]),
        }
        features.append(feat)

    feature_df = pd.DataFrame(features)
    feature_df.set_index("window_start", inplace=True)

    print(f"[+] Extracted features for {len(feature_df)} time windows")
    print(f"    Features: {list(feature_df.columns)}")
    return feature_df


if __name__ == "__main__":
    df = extract_features("logs/security_logs.csv")
    print("\nSample features:")
    print(df.head(10).to_string())
