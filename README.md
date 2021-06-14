<p align="center"><img width=30.5% src="https://github.com/ddos-clearing-house/ddos_dissector/blob/3.0/media/header.png?raw=true"></p>




&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
![Python](https://img.shields.io/badge/python-v3.6+-blue.svg)
[![Build Status](https://api.travis-ci.com/joaoceron/new_dissector.svg?token=8TMUECLCUVrxas7wXfVY&branch=master)](https://travis-ci.com/github/joaoceron/new_dissector)
[![GitHub Issues](https://img.shields.io/github/issues/ddos-clearing-house/ddos_dissector)](https://github.com/ddos-clearing-house/ddos_dissector/issues)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
<img alt="GitHub commits since tagged version" src="https://img.shields.io/github/last-commit/ddos-clearing-house/ddos_dissector">

 <p align="center">
  <img width=30.5% src="https://github.com/ddos-clearing-house/dddosdb-in-a-box/blob/master/imgs/concordia-logo.png?raw=true">
 <p align="center"><img width=30.5% src="https://github.com/ddos-clearing-house/dddosdb-in-a-box/blob/master/imgs/No-More-DDoS-2-removebg-preview.png?raw=true"></p>
</p>

## DDoS DISSECTOR - Overview

DDoS_Dissector is responsible for summarizing DDoS attack traffic from stored traffic (pcap/flows). The key point is to build a heuristic/algorithm that can find similarities in the analyzed network traffic. 

In order to improve software efficiency, we are working on software components that can parse specific DDoS attacks, such as amplification and TCP Syn flood attacks. 

## Docker container

You can run DDoS_Dissector in a docker container. This way, you do not have to install
dependencies yourself and can start analyzing traffic captures right away.
The only requirement is to have [Docker](https://docs.docker.com/get-docker/) installed and running.

1. Clone this repository: `git clone https://github.com/ddos-clearing-house/ddos_dissector`
2. Build the docker image (669MB): `cd ddos_dissector; docker build -t dissector .`
3. Run dissector in a docker container (from the root of this repository):
    ```bash
    docker run -v $(pwd):/app dissector [arguments]
    ```
    **Note:** the volume specified with the `-v` flag mounts the current working directory to /app in the
docker container. Make sure you are in the root of this repository when calling the command and the pcap file you wish to analyze is also somewhere in this directory. Alternatively, add an additional volume to mount the location of your traffic file to the docker container, e.g., `-v /home/me/pcaps:/data`
   
    **Note:** If you have an instance of [DDoSDB](https://github.com/ddos-clearing-house/ddosdb) running locally on localhost and wish to upload fingerprints to it, 
add the following flag to the `docker run` command to use the host network instead of the docker-created network: `--network="host"`

    **Example command:**
   ```bash
   docker run --network="host" -v $(pwd):/app dissector -f /app/pcap_samples/sample1.pcap -u -n --host https://localhost/ --user user --passwd pass
   ```
   

## Install locally

### Dependencies

Be sure to have tskark[1] and nfdump[2] in your path.

- [1] https://tshark.dev/
- [2] https://github.com/phaag/nfdump


### Installation and use

1. Install the dissector

```bash
git clone https://github.com/ddos-clearing-house/ddos_dissector;
cd ddos_dissector;
pip install -r requirements.txt
```

2. Provide a pcap to be analized

We do provide some pcap samples. Check the directory *pcap_samples*. Note, you can provide any type of cap and the size of pcap will influence the processing time. We encourage the use of a  medium-size file (25Mbytes to 50Mbytes). You can find other pcap samples online, such as in the this <a href="https://www.simpleweb.org/wiki/index.php/Traces#Datasets_for_Booter_attacks">repository</a>.

3. Run the software
```
./ddos_dissector.py -f pcap_samples/sample1.pcap --summary
```

4. Check the generated fingerprint (json file). 

```json
<snip>

{
  "attack_vector": [
    {
      "dns_qry_type": [
        1
      ],
      "ip_proto": [
        "UDP"
      ],
      "highest_protocol": [
        "DNS"
      ],
      "dns_qry_name": [
        "a.packetdevil.com"
      ],
      "frame_len": [
        1514
      ],
      "udp_length": [
        4103
      ],
      "srcport": [
        53
      ],
      "fragmentation": [
        true
      ],
      "src_ips": [
        "ommited"
      ],
      "attack_vector_key": "66f2e83fde0e6351d3f5ad967c6230aa3b60dbc498ad13b074296cb5f84c7734",
      "one_line_fingerprint": "{'dns_qry_type': 1, 'ip_proto': 'UDP',
      'highest_protocol': 'DNS', 'dns_qry_name': 'a.packetdevil.com',
      'frame_len': 1514, 'udp_length': 4103, 'srcport': 53,
      'fragmentation': True, 'src_ips': 'omitted'}"
    }
  ],
  "start_time": "2013-08-14 23:04:00",
  "duration_sec": 0.16,
  "total_dst_ports": 4649,
  "avg_bps": 143426993,
  "total_packets": 16471,
  "ddos_attack_key": "44518107642b9ac7098174a16cbf220395c862bf26389c734e0b109b318e9291",
  "key": "44518107642b9ac",
  "total_ips": 2065,
  "tags": [
    "AMPLIFICATION",
    "DNS",
    "FRAGMENTATION",
    "UDP_SUSPECT_LENGTH",
    "DNS_QUERY",
    "SINGLE_VECTOR_ATTACK"
  ]
}
<snip>
```


   <p align="center"><img width=80% src="https://github.com/ddos-clearing-house/ddos_dissector/blob/3.0/media/dissector.gif"></p>



<!-- <p align="center"><img width=95% src="https://github.com/anfederico/Waldo/blob/master/media/Schematic.png"></p> -->

<br>

## Usage

<!-- <img src="https://github.com/anfederico/Clairvoyant/blob/master/media/Learning.gif" width=40%> -->

````

 _____  _____        _____ _____  ____
|  __ \|  __ \      / ____|  __ \|  _ \
| |  | | |  | | ___| (___ | |  | | |_) |
| |  | | |  | |/ _ \\___ \| |  | |  _ <
| |__| | |__| | (_) |___) | |__| | |_) |
|_____/|_____/ \___/_____/|_____/|____/

Upload using configuration file [ddosdb.conf]
usage: ddos_dissector.py [options]

optional arguments:
  -h, --help            show this help message and exit
  --version             print version and exit
  -v, --verbose         print info msg
  -d, --debug           print debug info
  -q, --quiet           ignore animation
  --status              check available repositories
  -s, --summary         present fingerprint evaluation summary
  -u, --upload          upload to the selected repository
  --log [LOG]           Log filename. Default =./log.txt"
  --fingerprint_dir [FINGERPRINT_DIR]
                        Fingerprint storage directory. Default =./fingerprints"
  --config [CONFIG]     Configuration File. Default =./ddosdb.conf"
  --host [HOST]         Upload host.
  --user [USER]         repository user.
  --passwd [PASSWD]     repository password.
  -g, --graph           build dot file (graphviz). It can be used to plot a visual representation
                         of the attack using the tool graphviz. When this option is set, youn will
                         received information how to convert the generate file (.dot) to image (.png).
  -f [FILENAME], --filename [FILENAME]

Example: ./ddos_dissector.py -f ./pcap_samples/sample1.pcap --summary --upload
````

## Examples

```
./ddos_dissector.py -f pcap_samples/sample1.pcap --summary [process file and show evaluation function]
./ddos_dissector.py -f pcap_samples/sample1.pcap --verbose [provide details about the pcap processing]
./ddos_dissector.py -f pcap_samples/sample1.pcap -g        [generate a .dot file used to represent a graphical visualization]
```


<hr>
<h3>Simple Visualization</h3>
<hr>

Dissector can generate [dot files](https://en.wikipedia.org/wiki/DOT_(graph_description_language)) to provide an attack graphical representation. We combine all the source and destination IPs to determine the attack concentration and spot the attack target.


<p align="center"><img width=80% border=2 src="https://github.com/ddos-clearing-house/ddos_dissector/blob/3.0/media/dot2.gif?raw=true"></p>

The animation below shows this process. Once the fingerprint is generated a dot file is also generated (upon request). This dot file can be converted to an image using the software [graphiz](https://graphviz.org/), as illustrated. The red tuples represent the traffic that matches the fingerprint and the green one represents the remaining.
 

## DDoS Fingerprints: the process behind fingerprint generation

The Dissector’s task is to processes DDoS network traffic (e.g., in the form of a PCAP file), identify attack characteristics (e.g., protocol, ports, source IPs, packet payload), and generate a fingerprint.

 <p align="center">
  <img width=60.5% src="https://raw.githubusercontent.com/ddos-clearing-house/ddos_dissector/3.0/media/fingerprints_classification.png"> <br>
 Figure 1: Fingerprint generation process.
</p>

The processing pipeline of the Dissector consists of two components: 

__Attack Profiler__: creates profiles from the sampled attack traffic. It determines the protocols and services involved in the attack and identifies a set of attributes relevant for classifying the attack. Attributes are either types of packet headers (e.g., HTTP headers, DNS requests, packet payloads, source, and destination IPs) or “higher-level” level type of attributes such as the suspected nature of the attack (e.g., amplification or ransomware-based DDoS).

__Attack Classifier__: calculates the values for each of the attributes in the profile, aiming to identify patterns and similarities. This classification could be done using simple heuristics based on the number of occurrences or using algorithms to determine the type of attack (e.g., a classifier that can assess if an attack is an amplification attack or not). 


This process is not straight forward for some attacks. So, we have decided to build one methodology per attack type. For instance, amplification attacks, volumetric attacks, multiprotocol, spoofed, and application-layer attacks. 
As soon we detect a characteristic that reveals the attack type, the traffic is processed using the proper methodology tailed for the attack type. In cases in which we could not identify the attack type, we process it using a generic heuristic based on protocol field frequency. In the end, this process provides a set of traffic characteristics that will be translated to a JSON file.

### Fingerprints

Fingerprint is the a JSON file generated by the Dissector and describes:

* protocol fields that describes the characteritics of the attack (e.g., HTTP headers, DNS requests, packet payloads, source, and destination IPs)
* stats regarding the attack (average bit per second, number of packets, a total of IPs);
* label attacks using tags (Amplification, NTP, volumetric attack, layer 7).

 <p align="center">
  <img width=60.5% src="https://github.com/ddos-clearing-house/ddos_dissector/blob/3.0/media/fingerprint.png?raw=true"> <br>
 Figure 2: DDoS attack fingerprint sample.
</p>

The fingerprint format is flexible. We have defined the mandatory fields in the schema (protocols and source IPs) and other information could be easily added. This is important because new attack types may require fields that are not present in the current fingerprint schema. This flexibility is also important to develop mitigation rules (e.g., a Snort or IP Tables rule that filters out specific address ranges), since the DDoS Clearing House also contains a tool (the Converter) which build mitigation rules based on fingerprints. 

The current version support evaluate a set of fields per protocol. Table 1 shows the fields used for PCAP files.

Attributes   | Protocols
------------ | -------------
DNS query name | DNS 
DNS query type |DNS
Ethernet Type | Ethernet
Ethernet Frame Length | Ethernet
HTTP Request | HTTP
HTTP Response  | HTTP
HTTP User Agent | HTTP
ICMP type | ICMP
ICMP code | ICMP
IP destination | IP
IP Flags | IP
IP Fragmentation offset | IP
IP proto | IP
IP source | IP 
IP TTL | IP
NTP priv reqcode | NTP
TCP destination port | TCP
TCP destination port | TCP
TCP flags | TCP
TCP source port | TCP
UDP destination port | UDP
UDP Length | UDP
UDP source port | UDP
[Table 1: Subset of attributes extract from PCAP files.]

In contrast, when processing a FLOW file, fewer attributes are present. Usually, flow file formats are sampled, they may have different sample rates and different sets of attributes. However, they have a standard set of attributes that are present in most of the file formats. Table 2 shows the attributes that the Dissector uses to determine the unique characteristics of the attack.  

Attributes   | Protocols
------------ | -------------
ICMP code | ICMP 
ICMP type | ICMP
In bytes | IP
In packets | IP
IP destination | IP 
IP proto | IP
IP source | IP
IP TTL | IP
TCP destination port | TCP
TCP flags | TCP
TCP source port | TCP
TCP Type of Service | TCP
UDP destination port | UDP
UDP source port | UDP
[Table 2: Subset of attributes extract from FLOW files.]

This means that our fingerprints could have the set of attributes described in the Table 1 and Table 2.

We are aware that this set of attributes might not cover all types of attacks. However, so far, they have been effective in most of the analyzed cases, such as flood and amplification attacks. Dissector development is an ongoing process and new attributes could be added in the future to map novel types of DDoS attacks.


