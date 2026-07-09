from flask import Flask, render_template_string
import json

app = Flask(__name__)


@app.route("/")
def dashboard():

    with open("alerts.json", "r") as file:
        alerts = json.load(file)

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
    border-left: 8px solid red;
}

.high {
    color: red;
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

<div class="alert">

<h2>{{ alert.type }}</h2>

<p>
Severity:
<span class="high">
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