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

DDos_Dissector is responsible for summarizing DDoS attack traffic from stored traffic (pcap/flows). The key point is to build a heuristic/algorithm that can find similarities in the analyzed network traffic. 

In order to improve software efficiency, we are working on software components that can parse specific DDoS attacks, such as amplification and TCP Syn flood attacks. 

## How to start?

1. Install the dissector

```bash
git clone https://github.com/ddos-clearing-house/ddos_dissector
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
  "dns_qry_type": [
    255
  ],
  "ip_proto": [
    "UDP"
  ],
  "highest_protocol": [
    "DNS"
  ],
  "dns_qry_name": [
    "evil.com"
  ],
  "eth_type": [
    "0x00000800"
  ],
  "srcport": [
    53
  ],
  "fragmentation": [
    false
  ],
  "tags": [
    "DNS",
    "DNS_QUERY",
    "AMPLIFICATION"
  ],  
"start_time": "2013-08-14 23:32:40",
"total_dst_ports": 1043,
"avg_bps": 28406714,
"total_packets": 19183,
"total_ips": 393, 
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
  --config [CONFIG]     Configuration File. Default =./ddosdb.conf"
  --host [HOST]         Upload host.
  --user [USER]         repository user.
  --passwd [PASSWD]     repository password.
  -g, --graph           build dot file (graphviz). It can be used to plot a visual representation
                         of the attack using the tool graphviz. When this option is set, youn will
                         received information how to convert the generate file (.dot) to image (.png).
  -f [FILENAME], --filename [FILENAME]

Example: ./ddos_dissector.py -f ./pcap_samples/sample1.pcap --summary --upload

Input file not provided. Use '-f' for that.
````

## Examples

```
./ddos_dissector.py -f pcap_samples/sample1.pcap --summary [process file and show evaluation function]
./ddos_dissector.py -f pcap_samples/sample1.pcap --verbose [provide details about the pcap processing]
./ddos_dissector.py -f pcap_samples/sample1.pcap -g        [generate a .dot file used to represent a graphical visualization]
```

<p align="center"><img width=80% border=2 src="https://github.com/ddos-clearing-house/ddos_dissector/blob/3.0/media/dot2.gif?raw=true"></p>

- Green: benign traffic
- Red:  malicious traffic 
 

## DDoS Fingerprints: the process behind fingerprint generation

An important component in this sharing infrastructure is the software “ddos-dissector”. It is responsible for analyzing DDoS traffic and extract a set of characteristics (protocol, ports, source IPs, packet payload) that identify the DDoS attack pattern. Figure 1 describes the overall process used to generate the fingerprints.  

 <p align="center">
  <img width=60.5% src="https://raw.githubusercontent.com/ddos-clearing-house/ddos_dissector/3.0/media/fingerprint_classification.png"> <br>
 Figure 1: Fingerprint generation process.
</p>

To understand the attack traffic pattern, we have defined a pipeline composed of two processes: attack vector filtering and classification heuristic. In the first, we identify the abnormal traffic generated by the attack and, in the second one, we determine the pattern that described it. 

### Network traffic analysis

The system expects to receive a DDoS traffic as input, either packets data or flow data captured from the received attack. It is important to highlight that, since we are not proposing a DDoS detection tool but a software to summarize the characteristics of DDoS traffic. 

Upon this traffic is provide to the system we perform a set of analysis to identify the attack vector used in the DDoS. In order to develop a generic solution, we should consider different aspects of the network traffic and so we built a heuristic to classify them. Next, we describe the main processes of our solution.

__Data profiling__: it is the process of evaluating the input file and determine informative summaries about the provided data. Initially, we identify the attack targets (destination IP addresses), protocol distribution, and the attackers (source IPs). In this way, we can figure out traffic outliers and determine the attack vectors. For example, a determined attack is composed of 90% of packets of UDP packets, and 99% of them are originated from a unique IP address. This scheme reveals an attack vector, which is: UDP traffic originated by the identified IP address. 

In this context, to determine the outliers of the analyzed dataset is helpful. We could implement this process of finding outliers using different methodologies (machine learning, statistic means, and others). We opted to use lightweight statistic methods to detect traffic outliers, such as z-score and frequency. Z-score is a statistic value that represents the number of standard deviations from the mean, useful to find outliers. By combining z-score and frequency (number of packets with certain characteristics) has shown good results to filter DDoS traffic.

__Cluster attack traffic characteristics__: once we have the filtered DDoS traffic, we could identify traffic similarity. This traffic regularly has a network pattern that reveals its signature (fingerprint). In some cases, however, this network pattern is composed of multiples attack vectors. Attackers may use different attack vectors to turn the mitigation process harder. In such a way, after processing the attack outliers we cluster network patterns to determine the attack vectors present in the input file. 

This process is not straight forward for some attacks. So, we have decided to build one methodology per attack type. For instance, amplification attacks, volumetric attacks, multiprotocol, spoofed, and application-layer attacks. 
As soon we detect a characteristic that reveals the attack type, the traffic is processed using the proper methodology tailed for the attack type. In cases in which we could not identify the attack type, we process it using a generic heuristic based on protocol field frequency. In the end, this process provides a set of traffic characteristics that will be translated to a JSON file.

__Generate fingerprints__: this process consists of a) the identified characteristics; b) add stats regarding the attack (average bit per second, number of packets, a total of IPs); c) label attacks using tags (Amplification, NTP, volumetric attack, layer 7); and d) aggregating this information into a JSON file. 


## Acknowledge

The development of the clearing house was partly funded by the European Union’s Horizon 2020 Research and Innovation program under Grant Agreement No 830927. It will be used by the Dutch National Anti-DDoS Coalition, a self-funded public-private initiative to collaboratively protect Dutch organizations and the wider Internet community from DDoS attacks. Websites: https://www.concordia-h2020.eu/ and https://www.nomoreddos.org/en/
