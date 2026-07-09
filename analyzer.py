import json
from database import save_alert

print("================================")
print("        SentinelSIEM v0.2")
print("     Security Monitoring Tool")
print("================================")


log_file = "linux_auth.log"

print("\nAnalyzing:", log_file)


file = open(log_file, "r")

logs = file.readlines()


failed_logins = 0

alerts = []

alert_records = []

source_ips = []

suspicious_logins = []

privilege_events = []

ssh_failures = []


for log in logs:

    # Original failed login detection
    if "FAILED LOGIN" in log:

        failed_logins += 1

        alerts.append(log.strip())

        ip = log.split("from")[-1].strip()

        source_ips.append(ip)


    # Suspicious external login detection
    if "logged in from 185." in log:

        suspicious_logins.append(log.strip())


    # Privilege escalation detection
    if "ROOT privileges" in log:

        privilege_events.append(log.strip())


    # Linux SSH failed login detection
    if "Failed password" in log and "sshd" in log:

        ssh_failures.append(log.strip())



print("\nSecurity Analysis Complete")

print("-------------------------")

print("Failed Login Attempts:", failed_logins)

print("SSH Failures Detected:", len(ssh_failures))



# Brute Force Detection

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



# Suspicious Login Detection

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



# Privilege Escalation Detection

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



# SSH Brute Force Detection

if len(ssh_failures) >= 3:

    ssh_alert = {

        "severity": "HIGH",

        "type": "SSH Brute Force Attack",

        "source_ip": ssh_failures[0].split("from")[-1].split("port")[0].strip(),

        "attempts": len(ssh_failures),

        "threat_score": 85,

        "events": ssh_failures

    }


    alert_records.append(ssh_alert)



    print("\nALERT LEVEL:", ssh_alert["severity"])

    print("Threat:", ssh_alert["type"])

    print("Source IP:", ssh_alert["source_ip"])

    print("Attempts:", ssh_alert["attempts"])

    print("Threat Score:", ssh_alert["threat_score"], "/100")

    print("\nEvents:")


    for event in ssh_alert["events"]:

        print("-", event)



file.close()



# Save alerts to database

for alert in alert_records:

    save_alert(alert)



# Save JSON report

with open("alerts.json", "w") as output:

    json.dump(alert_records, output, indent=4)



print("\nAlerts saved to alerts.json")