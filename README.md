# SentinelSIEM 🛡️

A Python-based Security Information and Event Management (SIEM) prototype that analyzes security logs, detects suspicious activity, generates alerts, and displays security events through a Flask web dashboard.

## Overview

SentinelSIEM is a cybersecurity monitoring tool designed to simulate a basic Security Operations Center (SOC) workflow.

The project analyzes authentication logs, detects brute-force login attempts, identifies suspicious source IP addresses, assigns threat scores, and displays alerts through a web-based dashboard.

## Features

* Security log analysis
* Failed login detection
* Brute-force attack detection
* Source IP identification
* Threat scoring system
* JSON alert generation
* Flask web dashboard
* Automated security alert reporting

## Project Architecture

```
Security Logs
      |
      v
Log Analyzer
      |
      v
Detection Rules
      |
      v
Alert Generator
      |
      v
alerts.json
      |
      v
Flask Dashboard
```

## Technologies Used

* Python 3
* Flask
* JSON
* Git/GitHub

## Example Detection

### Input Log

```
FAILED LOGIN user admin from 192.168.1.50
FAILED LOGIN user admin from 192.168.1.50
FAILED LOGIN user admin from 192.168.1.50
```

### Generated Alert

```
ALERT LEVEL: HIGH

Threat: Brute Force Attack

Source IP: 192.168.1.50

Attempts: 3

Threat Score: 80/100
```

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Navigate into the project:

```bash
cd SentinelSIEM
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate the environment:

Mac/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the security analyzer:

```bash
python3 analyzer.py
```

Launch the dashboard:

```bash
python3 app.py
```

Open your browser:

```
http://127.0.0.1:5000
```

## Future Improvements

* Additional threat detection rules
* Database integration
* Real-time log monitoring
* Threat intelligence integration
* User authentication
* Advanced reporting features

## Purpose

This project was created as a cybersecurity portfolio project to demonstrate skills in:

* Security monitoring
* Log analysis
* Threat detection
* Python automation
* SIEM concepts
* Blue team security operations

