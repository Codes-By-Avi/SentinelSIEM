from flask import Flask, render_template_string
import sqlite3

app = Flask(__name__)


@app.route("/")
def dashboard():

    connection = sqlite3.connect("sentinelsiem.db")

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("SELECT * FROM alerts")

    alerts = cursor.fetchall()

    connection.close()


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

</style>

</head>


<body>


<h1>🛡️ SentinelSIEM Dashboard</h1>

<h2>Security Alerts</h2>


{% for alert in alerts %}


<div class="alert {{ alert.severity.lower() }}">


<h2>{{ alert.alert_type }}</h2>


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


</div>


{% endfor %}


</body>

</html>

"""


    return render_template_string(page, alerts=alerts)



app.run(debug=True)