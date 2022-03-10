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
