# DDoS Fingerprint format

DDoS Fingerprints are JSON files that describe the characteristics of a DDoS attack. They are distilled from DDoS 
network captures using the [_dissector_](https://github.com/ddos-clearing-house/ddos_dissector) module of the DDoS Clearing House. The input to the dissector can be FLOW data
or PCAPS.

Fingerprints generated from PCAP data may contain more detailed characteristics than those generated from FLOW files,
but their overall structure is the same.

Each fingerprint contains summary statistics of the entire attack, such as average bits/s, duration, and number of packets.
Each fingerprint also contains an array of _attack vectors_ that each describe one of the vectors that make up this attack.
Fingerprints have at least one attack vector. Examples are DNS amplification, TCP SYN Flood, NTP amplification, etc.
Each attack vector describes the traffic that belongs to that vector and includes information like source IP addresses,
targeted ports, and IP protocol.

When a fingerprint is uploaded to [DDoS-DB](https://github.com/ddos-clearing-house/ddosdb) - the database that stores fingerprints and allows sharing them between members 
of an anti-DDoS coalition - some additional fields are added.

The following fields are defined for fingerprints generated from FLOW data. Additional fields may be added to each attack
vector when using a PCAP as input, such as DNS query name and NTP request type.


### Summary statistics
| <br/>**Field name** | **Description**                                                                                         | **Data type**                                   |
|---------------------|---------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| `attack_vectors`    | Array of attack vectors that make up this attack(see below)                                             | Array of objects (see Attack Vector statistics) |
| `target`            | IP address or subnet of the attack target, or "Anonymous" (when uploaded to DDoS-DB)                    | String                                          |
| `tags`              | Tags assigned to this attack, e.g. "Amplification attack", "Multi-vector attack", "TCP SYN flag attack" | Array of strings                                |
| `key`               | MD5 hash digest of the fingerprint, used as identifier and as file name of the fingerprint              | String                                          |
| `time_start`        | Timestamp of the start of the attack (time zone local to the attack target)                             | String                                          |
| `duration_seconds`  | Duration of the attack in seconds                                                                       | Integer                                         |
| `total_flows`       | Total number of flows in the attack capture                                                             | Integer                                         |
| `total_megabytes`   | Total volume of the attack in megabytes (MB)                                                            | Integer                                         |
| `total_packets`     | Total number of packet in the attack                                                                    | Integer                                         |
| `total_ips`         | Total number of unique source IP addresses from which attack traffic originated                         | Integer                                         |
| `avg_bps`           | Average number of bits/s during the attack                                                              | Integer                                         |
| `avg_pps`           | Average number of packets/s during the attack                                                           | Integer                                         |
| `avg_Bpp`           | Average number of Bytes per packet                                                                      | Integer                                         |

### Attack vectors
| **Field name**       | **Description**                                                                                                                                                                                                                                    | **Data type**                  |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| `service`            | Name of the service used in this attack vector, determined by the source port and protocol. e.g. UDP port 53 -> DNS. Or: "Unknown service" or "Fragmented IP packets" for the vector of packet fragments that cannot be assigned to another vector | String                         |
| `protocol`           | IP protocol, e.g. TCP, UDP, ICMP                                                                                                                                                                                                                   | String                         |
| `source_port`        | Source port of this attack vector, or "random"                                                                                                                                                                                                     | Integer or "random"            |
| `fraction_of_attack` | The fraction of the entire DDoS attack that this attack vector makes up \[0, 1\], not taking into account the vector of packet fragments (null)                                                                                                    | Float or null                  |
| `destination_ports`  | List of outlier destination ports (if any) with the corresponding fraction of the traffic, or "random". e.g. {"443": 0.65, "80": 0.35}. (The keys are strings because of the JSON format)                                                          | Map<String, Float> or "random" |
| `tcp_flags`          | List of outlier TCP flags (if any) with the corresponding fraction of the traffic,. e.g. {"...A....": 0.987}. null if the protocol is not TCP, or there are no outliers                                                                            | null or Map<String, Float>     |
| `nr_flows`           | Number of flows that contribute to this attack vector                                                                                                                                                                                              | Integer                        |
| `nr_packets`         | Number of packets in this attack vector                                                                                                                                                                                                            | Integer                        |
| `nr_megabytes`       | Number of megabytes sent through this attack vector                                                                                                                                                                                                | Integer                        |
| `time_start`         | Timestamp of the start of the attack vector: the first flow of this attack vector (timezone local to the attack target)                                                                                                                            | String                         |
| `duration_seconds`   | Duration of this attack vector in seconds (last timestamp - first timestamp)                                                                                                                                                                       | Integer                        |
| `source_ips`         | Array of unique IP addressed that sent traffic to the target on this attack vector                                                                                                                                                                 | Array of strings               |

### Added in DDoS-DB
| **Field name**     | **Description**                                                              | **Data type** |
|--------------------|------------------------------------------------------------------------------|---------------|
| `submitter`        | user account that submitted the fingerprint to DDoS-DB                       | String        |
| `submit_timestamp` | Timestamp of the upload (UTC)                                                | String        |
| `shareable`        | If this fingerprint can be shared with other users / other DDoS-DB instances | Boolean       |
| `comment`          | Comment added to the fingerprint                                             | Boolean       |