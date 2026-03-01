# AI-Powered SIEM System

A SIEM (Security Information and Event Management) system that uses machine learning to detect threats in security logs without needing any labeled training data.

## How It Works

The system runs a 6-step pipeline:

1. Generates realistic security logs with normal traffic and embedded attacks (brute force, port scan, DDoS, privilege escalation)
2. Groups logs into 5-minute time windows and calculates 8 features per window — things like event count, error ratio, failed logins, IP entropy
3. Feeds the features into an Isolation Forest model which learns what normal traffic looks like and flags anything that doesn't fit
4. Classifies each flagged anomaly into an attack type based on which features are abnormal
5. Triggers automated response playbooks based on the attack type and severity
6. Generates a security dashboard showing the detections

## Project Structure

```
siem_project/
├── main.py              # Runs the full pipeline
├── log_generator.py     # Creates synthetic logs with attack patterns
├── feature_engine.py    # Extracts features from raw logs
├── anomaly_detector.py  # Isolation Forest detection and scoring
├── alert_system.py      # Alerting and response playbooks
├── visualizer.py        # Dashboard generation
├── logs/                # Generated logs and alerts
└── output/              # Dashboard PNG
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install pandas numpy scikit-learn matplotlib
python3 main.py
```

## What It Detects

| Attack | What Happens | How the Model Catches It |
|--------|-------------|------------------------|
| Brute Force | 45 failed SSH logins in 1 minute | Spike in failed_logins and error_ratio |
| Port Scan | Rapid connections across many services | High unique_services with high event_count |
| DDoS | 60 high-volume HTTP requests in 45 seconds | Spike in event_count and avg_bytes |
| Privilege Escalation | Unauthorized root access attempts | High error_ratio with low event_count |

## Sample Output

```
🔴 [ALERT-0001] CRITICAL — DDOS_FLOOD
     Score       : -0.2658
     Events      : 62 | Errors: 97% | Failed Logins: 0
     Response Actions:
       → Enable rate limiting on affected service
       → Activate DDoS mitigation
       → Block offending IP ranges at edge

🟠 [ALERT-0002] HIGH — BRUTE_FORCE
     Score       : -0.2234
     Events      : 54 | Errors: 83% | Failed Logins: 45
     Response Actions:
       → Block source IP at firewall
       → Lock targeted user account for 30 minutes
```

## Built With

- Python
- scikit-learn (Isolation Forest)
- pandas / numpy
- matplotlib
