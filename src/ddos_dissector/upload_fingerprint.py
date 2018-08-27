import requests


def upload(pcap, fingerprint, username, password, key):
    """
    Upload a fingerprint and attack vector to DDoSDB
    :param pcap: Path to the pcap file
    :param fingerprint: Path to the fingerprint file
    :param username: DDoSDB username
    :param password: DDoSDB password
    :param key: ID to identify this attack, also the filename of the pcap_file.
    :return:
    """
    files = {
        "json": open(fingerprint, "rb"),
        "pcap": open(pcap, "rb")
    }
    headers = {
        "X-Username": username,
        "X-Password": password,
        "X-Filename": key
    }
    ddosdb_url = "https://ddosdb.org/"
    r = requests.post(ddosdb_url+"upload-file", files=files, headers=headers)

    return r.status_code
