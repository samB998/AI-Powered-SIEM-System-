"""
log_generator.py — Generates realistic synthetic security logs
Simulates normal traffic + multiple attack types:
  - Brute force login attempts
  - Port scanning
  - DDoS-style request floods
  - Privilege escalation attempts
"""

import random
import datetime
import csv
import os

USERS = ["admin", "alice", "bob", "charlie", "dave", "eve", "frank"]
ATTACKER_IPS = ["203.0.113.50", "198.51.100.77", "192.0.2.99"]
NORMAL_IPS = [f"10.0.0.{i}" for i in range(1, 30)]
SERVICES = ["ssh", "http", "https", "ftp", "smtp", "dns", "mysql"]
LOG_LEVELS = ["INFO", "WARNING", "ERROR", "CRITICAL"]

NORMAL_EVENTS = [
    ("INFO", "User login success", "ssh"),
    ("INFO", "Page request served", "http"),
    ("INFO", "File downloaded", "ftp"),
    ("INFO", "Email sent", "smtp"),
    ("INFO", "DNS query resolved", "dns"),
    ("INFO", "Database query executed", "mysql"),
    ("WARNING", "Slow query detected", "mysql"),
    ("INFO", "User logout", "ssh"),
    ("INFO", "SSL handshake completed", "https"),
]

ATTACK_EVENTS = {
    "brute_force": ("ERROR", "Failed login attempt", "ssh"),
    "port_scan": ("WARNING", "Connection to unusual port", "http"),
    "ddos": ("CRITICAL", "High volume request flood", "http"),
    "privilege_escalation": ("CRITICAL", "Unauthorized privilege change", "ssh"),
}


def generate_logs(output_path="logs/security_logs.csv", num_normal=500, seed=42):
    """Generate a CSV log file with normal + attack traffic."""
    random.seed(seed)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    logs = []
    base_time = datetime.datetime(2025, 3, 6, 8, 0, 0)

    # --- Normal traffic ---
    for i in range(num_normal):
        timestamp = base_time + datetime.timedelta(seconds=random.randint(0, 3600 * 8))
        level, message, service = random.choice(NORMAL_EVENTS)
        user = random.choice(USERS)
        src_ip = random.choice(NORMAL_IPS)
        bytes_transferred = random.randint(64, 5000)
        logs.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
            "user": user,
            "src_ip": src_ip,
            "service": service,
            "bytes": bytes_transferred,
        })

    # --- Attack: Brute force (burst of failed logins from attacker IP) ---
    attack_time = base_time + datetime.timedelta(hours=3, minutes=12)
    attacker_ip = ATTACKER_IPS[0]
    for i in range(45):
        timestamp = attack_time + datetime.timedelta(seconds=random.randint(0, 60))
        level, message, service = ATTACK_EVENTS["brute_force"]
        logs.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
            "user": "admin",
            "src_ip": attacker_ip,
            "service": service,
            "bytes": random.randint(64, 200),
        })

    # --- Attack: Port scan (rapid connections across services) ---
    scan_time = base_time + datetime.timedelta(hours=5, minutes=30)
    scanner_ip = ATTACKER_IPS[1]
    for i in range(35):
        timestamp = scan_time + datetime.timedelta(seconds=random.randint(0, 30))
        level, message, service = ATTACK_EVENTS["port_scan"]
        logs.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
            "user": "unknown",
            "src_ip": scanner_ip,
            "service": random.choice(SERVICES),
            "bytes": random.randint(40, 80),
        })

    # --- Attack: DDoS flood ---
    ddos_time = base_time + datetime.timedelta(hours=6, minutes=45)
    for i in range(60):
        timestamp = ddos_time + datetime.timedelta(seconds=random.randint(0, 45))
        level, message, service = ATTACK_EVENTS["ddos"]
        logs.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
            "user": "unknown",
            "src_ip": random.choice(ATTACKER_IPS),
            "service": "http",
            "bytes": random.randint(10000, 50000),
        })

    # --- Attack: Privilege escalation ---
    priv_time = base_time + datetime.timedelta(hours=7, minutes=10)
    for i in range(5):
        timestamp = priv_time + datetime.timedelta(seconds=random.randint(0, 120))
        level, message, service = ATTACK_EVENTS["privilege_escalation"]
        logs.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
            "user": "eve",
            "src_ip": ATTACKER_IPS[2],
            "service": service,
            "bytes": random.randint(100, 500),
        })

    # Sort by timestamp
    logs.sort(key=lambda x: x["timestamp"])

    # Write to CSV
    fieldnames = ["timestamp", "level", "message", "user", "src_ip", "service", "bytes"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(logs)

    print(f"[+] Generated {len(logs)} log entries -> {output_path}")
    return output_path


if __name__ == "__main__":
    generate_logs()
