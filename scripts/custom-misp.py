#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error
import ssl

MISP_URL = "https://192.168.6.3"
MISP_AUTH_KEY = "NOlJg7T1uDhYsnKcwmZ5gurry7WMsBOBGiAtsF3c"

def lookup_ioc(ioc_value):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        "Authorization": MISP_AUTH_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"value": ioc_value, "limit": 5}).encode("utf-8")
    req = urllib.request.Request(
        f"{MISP_URL}/attributes/restSearch",
        data=payload,
        headers=headers,
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            result = json.loads(response.read().decode())
            return result.get("response", {}).get("Attribute", [])
    except Exception as e:
        return []

def main():
    alert_file = sys.argv[1]
    with open(alert_file) as f:
        alert = json.load(f)
    src_ip = alert.get("data", {}).get("srcip", "")
    dst_ip = alert.get("data", {}).get("dstip", "")
    for ioc in [src_ip, dst_ip]:
        if ioc:
            matches = lookup_ioc(ioc)
            if matches:
                print(f"MISP IOC match found for {ioc}: {json.dumps(matches)}")

if __name__ == "__main__":
    main()
