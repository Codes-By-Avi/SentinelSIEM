THREAT_INTELLIGENCE = {

    "203.0.113.55": {
        "country": "Unknown",
        "reputation": "Malicious",
        "confidence": "High",
        "known_botnet": "Yes"
    },

    "192.168.1.50": {
        "country": "Internal Network",
        "reputation": "Internal Host",
        "confidence": "High",
        "known_botnet": "No"
    },

    "185.44.22.10": {
        "country": "Unknown",
        "reputation": "Suspicious",
        "confidence": "Medium",
        "known_botnet": "No"
    }

}


def lookup_ip(ip):

    return THREAT_INTELLIGENCE.get(
        ip,
        {
            "country": "Unknown",
            "reputation": "Unknown",
            "confidence": "Low",
            "known_botnet": "Unknown"
        }
    )