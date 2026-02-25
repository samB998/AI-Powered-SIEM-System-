"""
visualizer.py — Generates SIEM dashboard visualizations
Produces a multi-panel security dashboard saved as PNG.
"""

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np


def generate_dashboard(feature_df, results, output_path="output/siem_dashboard.png"):
    """
    Generate a 4-panel security dashboard.

    Panels:
      1. Event count timeline with anomaly markers
      2. Anomaly score over time
      3. Error ratio heatmap-style bar
      4. Feature correlation for anomalies vs normal
    """
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle("AI-SIEM SECURITY DASHBOARD", fontsize=16, fontweight="bold", y=0.98)
    fig.patch.set_facecolor("#0d1117")

    for ax in axes.flat:
        ax.set_facecolor("#161b22")
        ax.tick_params(colors="#c9d1d9", labelsize=8)
        ax.xaxis.label.set_color("#c9d1d9")
        ax.yaxis.label.set_color("#c9d1d9")
        ax.title.set_color("#c9d1d9")
        for spine in ax.spines.values():
            spine.set_color("#30363d")

    times = results.index
    normal_mask = results["is_anomaly"] == 0
    anomaly_mask = results["is_anomaly"] == 1

    # --- Panel 1: Event Timeline with Anomalies ---
    ax1 = axes[0, 0]
    ax1.fill_between(times, results["event_count"], alpha=0.3, color="#58a6ff")
    ax1.plot(times, results["event_count"], color="#58a6ff", linewidth=1.2, label="Events")
    ax1.scatter(times[anomaly_mask], results["event_count"][anomaly_mask],
                color="#f85149", s=80, zorder=5, label="Anomaly", edgecolors="white", linewidths=0.5)
    ax1.set_title("Event Count per Window", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Event Count")
    ax1.legend(fontsize=8, facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")
    ax1.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # --- Panel 2: Anomaly Score Timeline ---
    ax2 = axes[0, 1]
    colors = ["#f85149" if a else "#3fb950" for a in results["is_anomaly"]]
    ax2.bar(times, results["anomaly_score"], color=colors, width=0.003, alpha=0.8)
    ax2.axhline(y=0, color="#f0883e", linestyle="--", linewidth=1, alpha=0.7, label="Threshold")
    ax2.set_title("Anomaly Score (lower = more suspicious)", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Isolation Forest Score")
    ax2.legend(fontsize=8, facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # --- Panel 3: Error Ratio + Failed Logins ---
    ax3 = axes[1, 0]
    bar_width = 0.003
    ax3.bar(times, results["error_ratio"], color="#f85149", width=bar_width, alpha=0.7, label="Error Ratio")
    ax3_twin = ax3.twinx()
    ax3_twin.plot(times, results["failed_logins"], color="#f0883e", linewidth=1.5,
                  marker="o", markersize=3, label="Failed Logins")
    ax3_twin.tick_params(colors="#c9d1d9", labelsize=8)
    ax3_twin.yaxis.label.set_color("#c9d1d9")
    ax3.set_title("Error Ratio & Failed Logins", fontsize=11, fontweight="bold")
    ax3.set_ylabel("Error Ratio")
    ax3_twin.set_ylabel("Failed Logins")
    ax3.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    lines1, labels1 = ax3.get_legend_handles_labels()
    lines2, labels2 = ax3_twin.get_legend_handles_labels()
    ax3.legend(lines1 + lines2, labels1 + labels2, fontsize=8,
               facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")

    # --- Panel 4: Feature Comparison (Normal vs Anomaly) ---
    ax4 = axes[1, 1]
    compare_features = ["event_count", "error_ratio", "unique_ips", "failed_logins", "avg_bytes"]
    normal_means = results[normal_mask][compare_features].mean()
    anomaly_means = results[anomaly_mask][compare_features].mean()

    # Normalize for visual comparison
    max_vals = np.maximum(normal_means.values, anomaly_means.values)
    max_vals[max_vals == 0] = 1
    normal_normed = normal_means.values / max_vals
    anomaly_normed = anomaly_means.values / max_vals

    x = np.arange(len(compare_features))
    width = 0.35
    ax4.barh(x - width/2, normal_normed, width, label="Normal", color="#3fb950", alpha=0.8)
    ax4.barh(x + width/2, anomaly_normed, width, label="Anomaly", color="#f85149", alpha=0.8)
    ax4.set_yticks(x)
    ax4.set_yticklabels(compare_features, fontsize=9)
    ax4.set_title("Feature Profile: Normal vs Anomaly", fontsize=11, fontweight="bold")
    ax4.set_xlabel("Normalized Value")
    ax4.legend(fontsize=8, facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, dpi=150, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    print(f"[+] Dashboard saved to {output_path}")
    return output_path
