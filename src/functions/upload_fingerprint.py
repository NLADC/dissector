import json
import requests


def upload(pcap_file, fingerprint, username, password, key):
    files = {
        "json": ("output.json", json.dumps(fingerprint)),
        "pcap": open(pcap_file, "rb")
    }
    headers = {
        "X-Username": username,
        "X-Password": password,
        "X-Filename": key
    }
    r = requests.post("https://ddosdb.org/upload-file", files=files, headers=headers)

    print(r.status_code)
