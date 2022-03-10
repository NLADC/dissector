<div style="text-align: center; vertical-align: center">
<img src="media/logo-CONCORDIA.png" style="width: 30%; padding-right: 3%" alt="Concordia logo">
<img src="media/header.png" style="width: 25%; padding-right: 3%" alt="DDoS Clearing House logo">
<img src="media/nomoreddos.svg#gh-dark-mode-only" style="width: 30%; padding-right: 3%" alt="NoMoreDDoS logo">
<img src="media/nomoreddos-light.png#gh-light-mode-only" style="width: 30%; padding-right: 3%" alt="NoMoreDDoS logo">
</div>

<div style="text-align: center;">

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
[![GitHub Issues](https://img.shields.io/github/issues/ddos-clearing-house/ddos_dissector)](https://github.com/ddos-clearing-house/ddos_dissector/issues)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Last commit](https://img.shields.io/github/last-commit/ddos-clearing-house/ddos_dissector)
</div>

## DDoS Dissector

The Dissector summarizes DDoS attack traffic from stored traffic captures (pcap/flows). The resulting summary is in the
form of a DDoS Fingerprint; a JSON file in which the attack's characteristics are described.

## How to use

### Option 1: Docker

You can run DDoS Dissector in a docker container. This way, you do not have to install dependencies yourself and can
start analyzing traffic captures right away. The only requirement is to
have [Docker](https://docs.docker.com/get-docker/) installed and running.

1. Clone this repository: `git clone https://github.com/ddos-clearing-house/ddos_dissector`
2. Build the docker image: `cd ddos_dissector; docker build -t dissector .`
3. Run dissector in a docker container (from the root of this repository):
    ```bash
    docker run -i -v $(pwd):/app -v /path/to/data:/data dissector [options]
    ```
   **Note:** We create two volumes: one mounts the curretn working directory to /app, so dissector can save fingerprints
   to ./fingerprints in the current directory. We also mount a volume from the location of PCAP or FLOW files (here
   /path/to/data) to /data. We can now access those files in the docker container at /data/file

   **Note:** If you have an instance of [DDoSDB](https://github.com/ddos-clearing-house/ddosdb) running **locally** on
   localhost and wish to upload fingerprints to it, add the following flag to the `docker run` command to use the host's
   network instead of the docker-created network: `--network="host"`

   **Example command:**
   ```bash
   docker run --network="host" -v $(pwd):/app -v /home/me/data:/data dissector -f /data/capture1.nfdump --config local.ini --ddosdb --noverify
   ```

### Option 2: Install locally

1. Install the dependencies to read PCAPs (tshark) and Flows (nfdump):

- [1] https://tshark.dev/
- [2] https://github.com/phaag/nfdump

2. Install the Dissector

```bash
git clone https://github.com/ddos-clearing-house/ddos_dissector;
cd ddos_dissector;
```

Optionally create a python environment for the dissector and install the python requirements:

```bash
python -m venv ./python-venv
source python-venv/bin/activate
pip install -r requirements.txt
```

3. Get a traffic capture file to be analized

PCAP files should have the `.pcap` extension, Flows should have the `.nfdump` extension

3. Run the dissector

```
python src/main.py -f data/attack_traffic.nfdump --summary
```

## Options

```
    ____  _                     __            
   / __ \(_)____________  _____/ /_____  _____
  / / / / / ___/ ___/ _ \/ ___/ __/ __ \/ ___/
 / /_/ / (__  |__  )  __/ /__/ /_/ /_/ / /    
/_____/_/____/____/\___/\___/\__/\____/_/     

usage: main.py [-h] -f FILES [FILES ...] [--summary] [--output OUTPUT] [--target TARGET] [--config CONFIG] [--ddosdb] [--misp] [--noverify] [--debug] [--show-target]

options:
  -h, --help            show this help message and exit
  -f FILES [FILES ...], --file FILES [FILES ...]
                        Path to Flow / PCAP capture file(s)
  --output OUTPUT       Path to directory in which to save the fingerprint (default ./fingerprints)
  --config CONFIG       Path to DDoS-DB/MISP config file (default ./config.ini)
  --summary             Optional: print fingerprint without source addresses to stdout
  --target TARGET       Optional: target IP address or subnet of this attack
  --ddosdb              Optional: directly upload fingerprint to a DDoS-DB instance specified in config
  --misp                Optional: directly upload fingerprint to a MISP instance specified in config
  --noverify            Optional: Don't verify TLS certificates for MISP / DDoSDB
  --debug               Optional: show debug messages
  --show-target         Optional: Do NOT anonymize the target IP address / network in the fingerprint.

Example: python src/main.py -f /data/part1.nfdump /data/part2.nfdump --summary --config ./localhost.ini --ddosdb --noverify
```

## DDoS Fingerprint format

### [Click here](fingerprint_format.md)

## Example Fingerprints

**Note: numbers and addresses are fabricated but are inspired by real fingerprints.**

<details>
  <summary>(Click to expand) Fingerprint from FLOW data: Multivector attack with LDAP amplification and TCP SYN flood</summary>

  ```json
{
  "attack_vectors": [
    {
      "service": "HTTPS",
      "protocol": "TCP",
      "source_port": 443,
      "fraction_of_attack": 0.21,
      "destination_ports": {
        "443": 1.0
      },
      "tcp_flags": {
        "......S.": 0.704,
        "others": 0.296
      },
      "nr_flows": 7946,
      "nr_packets": 39900000,
      "nr_megabytes": 34530,
      "time_start": "2022-01-30 12:49:09",
      "duration_seconds": 103,
      "source_ips": [
        "75.34.122.98",
        "80.83.200.214",
        "109.2.17.144",
        "22.56.34.108",
        "98.180.25.16",
        ...
      ]
    },
    {
      "service": "LDAP",
      "protocol": "UDP",
      "source_port": 389,
      "fraction_of_attack": 0.79,
      "destination_ports": {
        "8623": 0.837,
        "36844": 0.163
      },
      "tcp_flags": null,
      "nr_flows": 38775,
      "nr_packets": 31365000,
      "nr_megabytes": 101758,
      "time_start": "2022-01-30 12:49:01",
      "duration_seconds": 154,
      "source_ips": [
        "75.34.122.98",
        "80.83.200.214",
        "109.2.17.144",
        "22.56.34.108",
        "98.180.25.16",
        ...
      ]
    }
  ],
  "target": "Anonymous",
  "tags": [
    "Amplification attack",
    "Multi-vector attack",
    "TCP",
    "TCP flag attack",
    "UDP"
  ],
  "key": "601fd86e43c004281210cb02d7f6d821",
  "time_start": "2022-01-30 12:49:01",
  "time_end": "2022-01-30 12:51:35",
  "duration_seconds": 154,
  "total_flows": 46721,
  "total_megabytes": 102897,
  "total_packets": 189744000,
  "total_ips": 4397,
  "avg_bps": 5193740008,
  "avg_pps": 960028,
  "avg_Bpp": 497
}
   ```

</details>

<details>
   <summary>(Click to expand) Fingerprint from PCAP data: DNS amplification attack with fragmented packets</summary>

```json
{
  "attack_vectors": [
    {
      "service": "Fragmented IP packets",
      "protocol": "UDP",
      "source_port": 0,
      "fraction_of_attack": null,
      "destination_ports": {
        "0": 1.0
      },
      "tcp_flags": null,
      "nr_packets": 4190,
      "nr_megabytes": 5,
      "time_start": "2013-08-15 01:32:40.901023+02:00",
      "duration_seconds": 5,
      "source_ips": [
        "75.34.122.98",
        "80.83.200.214",
        "109.2.17.144",
        "22.56.34.108",
        "98.180.25.16",
        ...
      ],
      "ethernet_type": {
        "IPv4": 1.0
      },
      "fragmentation_offset": {
        "0": 0.727,
        "1480": 0.247
      }
    },
    {
      "service": "DNS",
      "protocol": "UDP",
      "source_port": 53,
      "fraction_of_attack": 0.945,
      "destination_ports": "random",
      "tcp_flags": null,
      "nr_packets": 166750,
      "nr_megabytes": 21,
      "time_start": "2013-08-15 00:56:40.211654+02:00",
      "duration_seconds": 22,
      "source_ips": [
        "75.34.122.98",
        "80.83.200.214",
        "109.2.17.144",
        "22.56.34.108",
        "98.180.25.16",
        ...
      ],
      "ethernet_type": {
        "IPv4": 1.0
      },
      "fragmentation_offset": {
        "0": 1.0
      },
      "dns_query_name": {
        "ddostheinter.net": 0.999
      },
      "dns_query_type": {
        "A": 0.999
      }
    }
  ],
  "target": "227.213.154.241",
  "tags": [
    "UDP",
    "Fragmentation attack",
    "Amplification attack",
  ],
  "key": "2e8c013d61ccaf88a1016828c16b9f0e",
  "time_start": "2013-08-15 00:56:40.211654+02:00",
  "time_end": "2013-08-15 00:57:03.199791+02:00",
  "duration_seconds": 22,
  "total_packets": 176393,
  "total_megabytes": 22,
  "total_ips": 8044,
  "avg_bps": 8039206,
  "avg_pps": 8017,
  "avg_Bpp": 125
}
```

</details>

## Acknowledgment

<table style="border-collapse: collapse">
   <tr>
      <td>
         <img src="media/eu-flag.png" style="width: 75px" alt="EU Flag"/>
      </td>
      <td>
         This project has received funding from the European Union's Horizon 2020 <br>reseach and innovation program under grant agreement no. 830927.
      </td>
   </tr>
</table>
