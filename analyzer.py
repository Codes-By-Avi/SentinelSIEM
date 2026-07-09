import json
from database import save_alert

print("================================")
print("        SentinelSIEM v0.2")
print("     Security Monitoring Tool")
print("================================")

log_file = "sample.log"

print("\nAnalyzing:", log_file)

file = open(log_file, "r")

logs = file.readlines()

failed_logins = 0
alerts = []
alert_records = []
source_ips = []

suspicious_logins = []
privilege_events = []

for log in logs:

    if "FAILED LOGIN" in log:
        failed_logins += 1

        alerts.append(log.strip())

        ip = log.split("from")[-1].strip()

        source_ips.append(ip)

    if "logged in from 185." in log:
        suspicious_logins.append(log.strip())


    if "ROOT privileges" in log:
        privilege_events.append(log.strip())    
        


print("\nSecurity Analysis Complete")

print("-------------------------")

print("Failed Login Attempts:", failed_logins)


if failed_logins >= 3:

    alert_record = {
        "severity": "HIGH",
        "type": "Brute Force Attack",
        "source_ip": source_ips[-1],
        "attempts": failed_logins,
        "threat_score": 80,
        "events": alerts
}

    alert_records.append(alert_record)

    print("\nALERT LEVEL:", alert_record["severity"])
    print("Threat:", alert_record["type"])
    print("Attempts:", alert_record["attempts"])
    print("Source IP:", alert_record["source_ip"])
    print("Threat Score:", alert_record["threat_score"], "/100")

    print("\nEvents:")

    for alert in alert_record["events"]:
        print("-", alert)

else:
    print("\nNo major threats detected.")


if suspicious_logins:

    suspicious_alert = {
        "severity": "MEDIUM",
        "type": "Suspicious External Login",
        "source_ip": suspicious_logins[0].split("from")[-1].strip(),
        "attempts": 1,
        "threat_score": 50,
        "events": suspicious_logins
    }

    alert_records.append(suspicious_alert)

    print("\nALERT LEVEL:", suspicious_alert["severity"])
    print("Threat:", suspicious_alert["type"])
    print("Source IP:", suspicious_alert["source_ip"])
    print("Threat Score:", suspicious_alert["threat_score"], "/100")


if privilege_events:

    privilege_alert = {
        "severity": "HIGH",
        "type": "Privilege Escalation Attempt",
        "source_ip": "Unknown",
        "attempts": 1,
        "threat_score": 90,
        "events": privilege_events
    }

    alert_records.append(privilege_alert)

    print("\nALERT LEVEL:", privilege_alert["severity"])
    print("Threat:", privilege_alert["type"])
    print("Event:", privilege_events[0])
    print("Threat Score:", privilege_alert["threat_score"], "/100")


file.close()

for alert in alert_records:
    save_alert(alert)

with open("alerts.json", "w") as output:
    json.dump(alert_records, output, indent=4)

print("\nAlerts saved to alerts.json")