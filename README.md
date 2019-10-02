# DDoS Dissector Repository

This repository contains the development of the DDoS Dissector tool ([ddos_dissector_cli](https://github.com/jjsantanna/ddosdb/blob/master/src/ddos_dissector_cli.py)). This tools is intended to analyse post-mortem network traces that contain one or multiple DDoS attacks. The tool dissects the input network traffic (pcap, pcapng, netflow v5, v9, IPFIX\*, and Sflow\*) for extracting a summary of the main characteristics of each attack vector, called DDoS attack fingerprints. Each fingerprint is a .json format file. 

In addition to output DDoS attack fingerprint, the DDoS dissector also outputs per attack vector the filtered and anonymised network trace (containing ONLY the attack vector).

### Dependencies 
The list of dependencies and a bash-script can be found [here!](https://github.com/jjsantanna/ddosdb/blob/master/src/install_dependencies.sh). Instead of using the bash-script, you can manually install the python libraries (with `pip3 install -r src/requirements.txt`), [Tshark](https://www.wireshark.org/download.html), and [Bit-Twist](https://sourceforge.net/projects/bittwist).

### How to use it?
For testing the DDoS Dissector tool you must have a network trace that contains a DDoS attack (.pcap, .pcapng, netflow, ...). There are some attack traces made publicly available by [SimpleWeb](https://www.simpleweb.org/wiki/index.php/Traces#Booters_-_An_analysis_of_DDoS-as-a-Service_Attacks), by [The Centre for Research on Cryptography and Security of the Masaryk University](https://github.com/crocs-muni/ddos-vault/blob/master/DDoSaaSTraces),  by [CAIDA](https://www.caida.org/data/passive/ddos-20070804_dataset.xml), and others. You can also download any .pcap file from [ddosdb.org](http://ddosdb.org).

`python3 ddos_dissector_cli.py --input <attack_trace_path.pcap>`

The output (fingerprints, anonymized filtered attack vectors, and a log file) will be available in the folder 'output'
