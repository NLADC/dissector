# DDoS Fingerprint format

DDoS Fingerprints are JSON files that describe the characteristics of a DDoS attack. They are distilled from DDoS
network captures using the [_dissector_](https://github.com/ddos-clearing-house/ddos_dissector) module of the DDoS
Clearing House. The input to the dissector can be FLOW data or PCAPS.

Fingerprints generated from PCAP data may contain more detailed characteristics than those generated from FLOW files,
but their overall structure is the same.

Each fingerprint contains summary statistics of the entire attack, such as average bits/s, duration, and number of
packets. Each fingerprint also contains an array of _attack vectors_ that each describe one of the vectors that make up
this attack. Fingerprints have at least one attack vector. Examples are DNS amplification, TCP SYN Flood, NTP
amplification, etc. Each attack vector describes the traffic that belongs to that vector and includes information like
source IP addresses, targeted ports, and IP protocol.

When a fingerprint is uploaded to [DDoS-DB](https://github.com/ddos-clearing-house/ddosdb) - the database that stores
fingerprints and allows sharing them between members of an anti-DDoS coalition - some additional fields are added.

The following fields are defined for fingerprints generated from FLOW data. Fingerprints generated from PCAPs will not
include the fields related to the number of flows. Additional fields that can be extracted from PCAP files are listed
after these.

The datatype `Map<?, Float>` refers to a map of values to their corresponding fraction of traffic. E.g.: `http_method: {"GET": 0.85, "POST": 0.15}`

### Summary statistics

| <br/>**Field name**                      | **Description**                                                                                         | **Datatype**     |
|------------------------------------------|---------------------------------------------------------------------------------------------------------|------------------|
| `attack_vectors`                         | Array of attack vectors that make up this attack(see below)                                             | Array of objects |
| `target`                                 | IP address or subnet of the attack target, or "Anonymous" (when uploaded to DDoS-DB)                    | String           |
| `tags`                                   | Tags assigned to this attack, e.g. "Amplification attack", "Multi-vector attack", "TCP SYN flag attack" | Array of strings |
| `key`                                    | MD5 hash digest of the fingerprint, used as identifier and as file name of the fingerprint              | String           |
| `time_start`                             | Timestamp of the start of the attack (time zone local to the attack target)                             | DateTime         |
| `time_end`                               | Timestamp of the end of the attack (time zone local to the attack target)                               | DateTime         |
| `duration_seconds`                       | Duration of the attack in seconds                                                                       | Integer          |
| `total_flows` <br>(only from Flow files) | Total number of flows in the attack capture                                                             | Integer          |
| `total_megabytes`                        | Total volume of the attack in megabytes (MB)                                                            | Integer          |
| `total_packets`                          | Total number of packet in the attack                                                                    | Integer          |
| `total_ips`                              | Total number of unique source IP addresses from which attack traffic originated                         | Integer          |
| `avg_bps`                                | Average number of bits/s during the attack                                                              | Integer          |
| `avg_pps`                                | Average number of packets/s during the attack                                                           | Integer          |
| `avg_Bpp`                                | Average number of Bytes per packet                                                                      | Integer          |

### Attack vectors (excluding additional fields from PCAPs)

| **Field name**                        | **Description**                                                                                                                                                                                                                                    | **Data type**                  |
|---------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| `service`                             | Name of the service used in this attack vector, determined by the source port and protocol. e.g. UDP port 53 -> DNS. Or: "Unknown service" or "Fragmented IP packets" for the vector of packet fragments that cannot be assigned to another vector | String                         |
| `protocol`                            | IP protocol, e.g. TCP, UDP, ICMP                                                                                                                                                                                                                   | String                         |
| `fraction_of_attack`                  | The fraction of the entire DDoS attack that this attack vector makes up \[0, 1\], calculated from total bytes, not taking into account the vector of packet fragments (null)                                                                       | Float or null                  |
| `source_port`                         | Source port of this attack vector if the source port in combination with protocol is associated with a specific service (e.g. UDP/53 -> DNS), if not - see `destiantion_ports`                                                                     | Integer or "random"            |
| `destination_ports`                   | List of outlier destination ports (if any) with the corresponding fraction of the traffic, or "random". e.g. {"443": 0.65, "80": 0.35}. (The keys are strings because of the JSON format)                                                          | Map<String, Float> or "random" |
| `tcp_flags`                           | List of outlier TCP flags (if any) with the corresponding fraction of the traffic,. e.g. {"...A....": 0.987}. null if the protocol is not TCP, or there are no outliers                                                                            | null or Map<String, Float>     |
| `nr_flows` <br>(only from Flow files) | Number of flows that contribute to this attack vector                                                                                                                                                                                              | Integer                        |
| `nr_packets`                          | Number of packets in this attack vector                                                                                                                                                                                                            | Integer                        |
| `nr_megabytes`                        | Number of megabytes sent through this attack vector                                                                                                                                                                                                | Integer                        |
| `time_start`                          | Timestamp of the start of the attack vector: the first flow of this attack vector (timezone local to the attack target)                                                                                                                            | DateTime                       |
| `duration_seconds`                    | Duration of this attack vector in seconds (last timestamp - first timestamp)                                                                                                                                                                       | Integer                        |
| `source_ips`                          | Array of unique IP addressed that sent traffic to the target on this attack vector (truncated in the preview, and in the overview on DDoS-DB), the JSON file contains all IP addresses                                                             | Array of strings               |

### Added in DDoS-DB

| **Field name**     | **Description**                                                              | **Data type** |
|--------------------|------------------------------------------------------------------------------|---------------|
| `submitter`        | user account that submitted the fingerprint to DDoS-DB                       | String        |
| `submit_timestamp` | Timestamp of the upload (UTC)                                                | String        |
| `shareable`        | If this fingerprint can be shared with other users / other DDoS-DB instances | Boolean       |
| `comment`          | Comment added to the fingerprint                                             | String        |

## Additional fields added from PCAP data

PCAP files contain the packets themselves, and thus allows the extraction of more detailed fields for various attack
vectors. The following fields are added to fingerprints generated from PCAP files, or added to specific attack vectors.

### All PCAP fingerprints

| **Field name**  | **Description**                                                                                | **Data type**                   |
|-----------------|------------------------------------------------------------------------------------------------|---------------------------------|
| `ethernet_type` | The protocol encapsulated in the ethernet frame ([?](https://en.wikipedia.org/wiki/EtherType)) | Map<String, Float> or "random"  |
| `frame_len`     | length of ethernet frame in bytes                                                              | Map<Integer, Float> or "random" |

### IP-based attack vectors (most)

| **Field name**         | **Description**                 | **Data type**                   |
|------------------------|---------------------------------|---------------------------------|
| `fragmentation_offset` | fragmentation_offset of packets | Map<Integer, Float> or "random" |
| `ttl`                  | Time to live                    | Map<Integer, Float> or "random" |

### DNS attack vectors

| **Field name**   | **Description**                             | **Data type**                  |
|------------------|---------------------------------------------|--------------------------------|
| `dns_query_name` | query name of the DNS request (domain name) | Map<String, Float> or "random" |
| `dns_query_type` | Query type (e.g. A, TXT, AAAA, ANY)         | Map<String, Float> or "random" |

### HTTP(S) attack vectors

| **Field name**    | **Description**                      | **Data type**                  |
|-------------------|--------------------------------------|--------------------------------|
| `http_uri`        | URI of the HTTP request              | Map<String, Float> or "random" |
| `http_method`     | HTTP request method (e.g. GET, POST) | Map<String, Float> or "random" |
| `http_user_agent` | User agent string                    | Map<String, Float> or "random" |

### NTP attack vectors

| **Field name**    | **Description**  | **Data type**                   |
|-------------------|------------------|---------------------------------|
| `ntp_requestcode` | NTP request code | Map<Integer, Float> or "random" |

### ICMP attack vectors

| **Field name** | **Description**       | **Data type**                  |
|----------------|-----------------------|--------------------------------|
| `ICMP type`    | ICMP type (e.g. Echo) | Map<String, Float> or "random" |