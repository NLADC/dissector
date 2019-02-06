# DDoS Dissector and DDoSDB

DDoS Dissector repository -- for the development of a tool responsible for (1) dissecting a network traffic (pcap, pcapng, netflow v5, v9, IPFIX, and sflow), (2) identifying and generating DDoS attack fingerprints (.json file with a summary of the network characteristics of an attack vector) for each found attack vector, and (3) filtering and anonymising the input network trace (remaining only the attack vectors) 

### 1. Before analyse your DDoS attack data, please install the dependencies [here!](https://github.com/jjsantanna/ddosdb/blob/master/src/install_dependencies.sh)

Or manually do the following:

`pip3 install -r src/requirements.txt`

Install the following packages from your local package management system:
* tshark
* bittwist

### 2. The program to analyse DDoS attacks and generate fingerprints is [here!](https://github.com/jjsantanna/ddosdb/blob/master/src/ddos_dissector_cli.py).
