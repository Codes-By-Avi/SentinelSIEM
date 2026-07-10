# SentinelSIEM Architecture

```text
                    SentinelSIEM

        +------------------------------+
        |      Security Log Files       |
        |------------------------------|
        | sample.log                   |
        | linux_auth.log               |
        +--------------+---------------+
                       |
                       v
        +------------------------------+
        |     Detection Engine          |
        |------------------------------|
        | Brute Force                  |
        | SSH Brute Force              |
        | Suspicious Login             |
        | Privilege Escalation         |
        +--------------+---------------+
                       |
                       v
        +------------------------------+
        | Threat Intelligence          |
        |------------------------------|
        | IP Reputation                |
        | Country                      |
        | Confidence                   |
        | Botnet Status                |
        +--------------+---------------+
                       |
                       v
        +------------------------------+
        | SQLite Database              |
        |------------------------------|
        | Alerts                       |
        | Status                       |
        | Timestamps                   |
        +--------------+---------------+
                       |
                       v
        +------------------------------+
        | Flask Dashboard              |
        |------------------------------|
        | Search                       |
        | Severity Filter              |
        | CSV Export                   |
        | Investigation Workflow       |
        +------------------------------+
```