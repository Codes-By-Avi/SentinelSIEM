import json

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

for log in logs:

    if "FAILED LOGIN" in log:
        failed_logins += 1

        alerts.append(log.strip())

        ip = log.split("from")[-1].strip()

        source_ips.append(ip)


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


file.close()

with open("alerts.json", "w") as output:
    json.dump(alert_records, output, indent=4)

print("\nAlerts saved to alerts.json")