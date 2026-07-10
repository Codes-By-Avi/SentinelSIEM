from flask import Flask, render_template_string, redirect, send_file, request
import sqlite3
import csv
from database import update_alert_status

app = Flask(__name__)


@app.route("/investigate/<int:alert_id>")
def investigate(alert_id):

    update_alert_status(alert_id, "INVESTIGATED")

    return redirect("/")

@app.route("/export")
def export():

    connection = sqlite3.connect("sentinelsiem.db")

    cursor = connection.cursor()

    cursor.execute("SELECT * FROM alerts")

    alerts = cursor.fetchall()

    connection.close()


    with open("sentinelsiem_alerts.csv", "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "ID",
            "Severity",
            "Type",
            "Source IP",
            "Attempts",
            "Threat Score",
            "Timestamp",
            "Status"
        ])


        for alert in alerts:

            writer.writerow(alert[:8])


    return send_file(
        "sentinelsiem_alerts.csv",
        as_attachment=True
    )

@app.route("/")
def dashboard():

    search = request.args.get("search", "")

    severity_filter = request.args.get("severity", "ALL")


    connection = sqlite3.connect("sentinelsiem.db")

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()


    query = "SELECT * FROM alerts WHERE 1=1"

    values = []


    if search:

        query += " AND source_ip LIKE ?"

        values.append("%" + search + "%")


    if severity_filter != "ALL":

        query += " AND severity = ?"

        values.append(severity_filter)


    cursor.execute(query, values)

    alerts = cursor.fetchall()


    cursor.execute("SELECT * FROM alerts")

    all_alerts = cursor.fetchall()


    connection.close()



    total_alerts = len(all_alerts)


    high_alerts = sum(
        1 for alert in all_alerts
        if alert["severity"] == "HIGH"
    )


    medium_alerts = sum(
        1 for alert in all_alerts
        if alert["severity"] == "MEDIUM"
    )


    open_alerts = sum(
        1 for alert in all_alerts
        if alert["status"] == "OPEN"
    )


    investigated_alerts = sum(
        1 for alert in all_alerts
        if alert["status"] == "INVESTIGATED"
    )


    highest_score = max(
        [alert["threat_score"] for alert in all_alerts],
        default=0
    )



    page = """

<html>

<head>

<title>SentinelSIEM Dashboard</title>


<style>

body {

    font-family: Arial, sans-serif;

    background-color: #111827;

    color: white;

    padding: 40px;

}


h1 {

    color: #38bdf8;

}


.overview {

    background: #1f2937;

    padding: 25px;

    border-radius: 12px;

    margin-bottom: 30px;

}


.alert {

    background: #1f2937;

    padding: 25px;

    margin: 20px 0;

    border-radius: 12px;

    border-left: 8px solid;

}


.high {

    border-color: red;

    color: #ff6b6b;

    font-weight: bold;

}


.medium {

    border-color: orange;

    color: #fbbf24;

    font-weight: bold;

}


.score {

    font-size: 22px;

    font-weight: bold;

    color: #38bdf8;

}


.intel {

    background: #111827;

    padding: 15px;

    border-radius: 8px;

    margin-top: 15px;

}


button {

    background: #38bdf8;

    border: none;

    padding: 10px 15px;

    border-radius: 8px;

    cursor: pointer;

}


button:hover {

    background: #0ea5e9;

}


input, select {

    padding: 10px;

    border-radius: 6px;

    border: none;

}


</style>


</head>


<body>


<h1>🛡️ SentinelSIEM Dashboard</h1>


<div class="overview">


<h2>Security Overview</h2>


<p>Total Alerts: {{ total_alerts }}</p>

<p>High Severity: {{ high_alerts }}</p>

<p>Medium Severity: {{ medium_alerts }}</p>

<p>Open Alerts: {{ open_alerts }}</p>

<p>Investigated Alerts: {{ investigated_alerts }}</p>


<p class="score">
Highest Threat Score:
{{ highest_score }}/100
</p>


</div>



<h2>Search Alerts</h2>


<form method="get">


<input 
type="text"
name="search"
placeholder="Search IP address"
value="{{ search }}"
>


<select name="severity">

<option value="ALL">ALL</option>

<option value="HIGH">HIGH</option>

<option value="MEDIUM">MEDIUM</option>

</select>


<button type="submit">
Search
</button>


</form>




<h2>Security Alerts</h2>

<a href="/export">

<button>
📄 Export Alerts CSV
</button>

</a>


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
Attempts:
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



{% if alert.status == "OPEN" %}

<a href="/investigate/{{ alert.id }}">

<button>
Mark Investigated
</button>

</a>

{% endif %}



<p>
Detected:
{{ alert.timestamp }}
</p>

<div class="intel">

<h3>🌐 Threat Intelligence</h3>

<p>
Country:
{{ alert.country }}
</p>

<p>
Reputation:
{{ alert.reputation }}
</p>

<p>
Confidence:
{{ alert.confidence }}
</p>

<p>
Known Botnet:
{{ alert.known_botnet }}
</p>

</div>


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
        open_alerts=open_alerts,
        investigated_alerts=investigated_alerts,
        highest_score=highest_score,
        search=search
    )



app.run(debug=True)