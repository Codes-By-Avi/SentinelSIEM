from flask import Flask, render_template_string, redirect
import sqlite3
from database import update_alert_status

app = Flask(__name__)

@app.route("/investigate/<int:alert_id>")
def investigate(alert_id):

    update_alert_status(alert_id, "INVESTIGATED")

    return redirect("/")

@app.route("/")
def dashboard():

    connection = sqlite3.connect("sentinelsiem.db")

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("SELECT * FROM alerts")

    alerts = cursor.fetchall()

    connection.close()


    total_alerts = len(alerts)

    high_alerts = sum(
        1 for alert in alerts
        if alert["severity"] == "HIGH"
    )

    medium_alerts = sum(
        1 for alert in alerts
        if alert["severity"] == "MEDIUM"
    )

    highest_score = max(
        [alert["threat_score"] for alert in alerts],
        default=0
    )


    page = """

<html>

<head>

<title>SentinelSIEM Dashboard</title>

<style>

body {
    font-family: Arial;
    background-color: #f4f4f4;
    padding: 40px;
}

h1 {
    color: #222;
}

.alert {
    background: white;
    padding: 20px;
    margin: 20px 0;
    border-radius: 10px;
    border-left: 8px solid;
}

.high {
    border-color: red;
    color: red;
    font-weight: bold;
}

.medium {
    border-color: orange;
    color: orange;
    font-weight: bold;
}

.score {
    font-size: 20px;
    font-weight: bold;
}

.overview {
    background: white;
    padding: 20px;
    border-radius: 10px;
}


</style>

</head>


<body>


<h1>🛡️ SentinelSIEM Dashboard</h1>


<div class="overview">

<h2>Security Overview</h2>


<p>
Total Alerts:
{{ total_alerts }}
</p>


<p>
High Severity:
{{ high_alerts }}
</p>


<p>
Medium Severity:
{{ medium_alerts }}
</p>


<p class="score">
Highest Threat Score:
{{ highest_score }}/100
</p>


</div>



<h2>Security Alerts</h2>


{% for alert in alerts %}


<div class="alert">


<h2>
{{ alert.alert_type }}
</h2>


<p>
Severity:

<span class="{{ alert.severity.lower() }}">
{{ alert.severity }}
</span>

</p>


<p>
Source IP:
{{ alert.source_ip }}
</p>


<p>
Failed Attempts:
{{ alert.attempts }}
</p>


<p class="score">
Threat Score:
{{ alert.threat_score }}/100
</p>


<p>
Status:
{{ alert.status }}
</p>

<a href="/investigate/{{ alert.id }}">
<button>
Mark Investigated
</button>
</a>


<p>
Detected:
{{ alert.timestamp }}
</p>


</div>


{% endfor %}



</body>

</html>

"""


    return render_template_string(
        page,
        alerts=alerts,
        total_alerts=total_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        highest_score=highest_score
    )



app.run(debug=True)