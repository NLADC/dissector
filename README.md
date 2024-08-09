<div style="text-align: center; vertical-align: center">
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="media/logo-CONCORDIA.png" style="width: 30%; padding-right: 3%" alt="Concordia logo">
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="media/header.png" style="width: 25%; padding-right: 3%" alt="DDoS Clearing House logo">
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="media/nomoreddos.svg#gh-light-mode-only" style="width: 30%; padding-right: 3%" alt="NoMoreDDoS logo">
<img src="media/nomoreddos-light.png#gh-dark-mode-only" style="width: 30%; padding-right: 3%" alt="NoMoreDDoS logo">
</div>

<br/>

<div style="content-align: center;">

![Python](https://img.shields.io/badge/python-v3.9+-blue.svg)
[![GitHub Issues](https://img.shields.io/github/issues/ddos-clearing-house/ddos_dissector)](https://github.com/ddos-clearing-house/ddos_dissector/issues)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)
[![License](https://img.shields.io/badge/license-AGPL-blue.svg)](https://opensource.org/licenses/AGPL)
![Last commit](https://img.shields.io/github/last-commit/ddos-clearing-house/ddos_dissector)
</div>

# DDoS Dissector

The Dissector summarizes DDoS attack traffic from stored traffic captures (pcap/flows). The resulting summary is in the
form of a DDoS Fingerprint; a JSON file in which the attack's characteristics are described.

# How to use the Dissector

## Option 1: in Docker

You can run DDoS Dissector in a docker container. This way, you do not have to install dependencies yourself and can
start analyzing traffic captures right away. The only requirement is to
have [Docker](https://docs.docker.com/get-docker/) installed and running.

1. Pull the docker image from [docker hub](https://hub.docker.com/r/ddosclearinghouse/dissector): `docker pull ddosclearinghouse/dissector`
2. Run dissector in a docker container:
    ```bash
    docker run -i --network="host" \
    --mount type=bind,source=/abs-path/to/config.ini,target=/etc/config.ini \
    -v /abs-path/to/data:/data \
    ddosclearinghouse/dissector -f /data/capture_file [options]
    ```
   **Note:** We bind-mount the [config file](config.ini.example) with DDoS-DB and MISP tokens to `/etc/config.ini`, and create a volume mount for the location of capture files.
   We use the local network to also allow connections to a locally running instance of DDoS-DB or MISP. Fingerprints are saved in `your-data-volume/fingerprints`


## Option 2: Installed locally

1. Install the dependencies to read PCAPs (either pcap-converter or tshark+tcpdump) and Flows (nfdump):

   - PCAPs
     - either https://github.com/NLADC/pcap-converter
     - or https://tshark.dev/ and https://www.tcpdump.org/ 
   - Flows
     - https://github.com/phaag/nfdump


2. Clone the Dissector repository

    ```bash
    git clone https://github.com/ddos-clearing-house/ddos_dissector;
    cd ddos_dissector;
    ```

3. [Advised] create a python virtual environment or conda environment for the dissector and install the python requirements:

    Venv:
    ```bash
    python -m venv ./python-venv
    source python-venv/bin/activate
    pip install -r requirements.txt
    ```
    [Conda](https://docs.conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html):
    ```bash
    conda create -n dissector python=3.10
    conda activate dissector
    pip install -r requirements.txt
    ```

4. Get a traffic capture file to be analized (PCAP files should have the `.pcap` extension, Flows should have the `.nfdump` extension)

5. Run the dissector:
    ```bash
    python src/main.py -f data/attack_traffic.nfdump --summary
    ```

# Options

```
    ____  _                     __            
   / __ \(_)____________  _____/ /_____  _____
  / / / / / ___/ ___/ _ \/ ___/ __/ __ \/ ___/
 / /_/ / (__  |__  )  __/ /__/ /_/ /_/ / /    
/_____/_/____/____/\___/\___/\__/\____/_/     

usage: main.py [-h] -f FILES [FILES ...] [--summary] [--output OUTPUT] [--config CONFIG] [--nprocesses N] [--target TARGET] [--ddosdb]
               [--misp] [--graph] [--noverify] [--show-target] [--tshark] [--debug]

options:
  -h, --help            show this help message and exit
  -f FILES [FILES ...], --file FILES [FILES ...]
                        Path to Flow / PCAP file(s)
  --summary             Optional: print fingerprint without source addresses
  --output OUTPUT       Path to directory in which to save the fingerprint (default: ./fingerprints)
  --config CONFIG       Path to DDoS-DB and/or MISP config file (default: /etc/config.ini)
  --nprocesses N        Number of processes used to read and process PCAPs (default: number of CPU cores (#))
  --target TARGET       Optional: Specify target IP address of this attack (subnet currently unsupported)
  --ddosdb              Optional: Directly upload fingerprint to DDoS-DB
  --misp                Optional: Directly upload fingerprint to MISP
  --graph               Optional: Create graphs of the attack, stored alongside the fingerprint
  --noverify            Optional: Do not verify TLS certificates (accept self-signed certificates)
  --show-target         Optional: Do NOT anonymize the target IP address/network in the fingerprint
  --tshark              Optional: Force use of tshark/tcpdump over pcap-converter, even if it is present
  --debug               Optional: Show debug messages

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
      "duration_seconds": 0,
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
      "frame_len": {
        "1514": 0.684,
        "693": 0.173,
        "296": 0.057,
        "others": 0.086
      },
      "fragmentation_offset": {
        "0": 0.727,
        "1480": 0.247,
        "others": 0.026
      },
      "ttl": {
        "54": 0.159,
        "57": 0.142,
        "55": 0.123,
        "59": 0.119,
        "others": 0.457
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
      "frame_len": {
        "103": 0.695,
        "87": 0.208,
        "others": 0.097
      },
      "fragmentation_offset": {
        "0": 1.0
      },
      "ttl": {
        "120": 0.1,
        "119": 0.085,
        "121": 0.085,
        "118": 0.07,
        "others": 0.66
      },
      "dns_query_name": {
        "ddostheinter.net": 0.999
      },
      "dns_query_type": {
        "A": 0.999
      }
    }
  ],
  "target": "Anonymous",
  "tags": [
    "Fragmentation attack",
    "Amplification attack",
    "UDP"
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
         This project has received funding from the European Union's Horizon 2020 <br>research and innovation program under grant agreement no. 830927.
      </td>
   </tr>
</table>
