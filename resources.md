## Resources Catalog

| field | description |
|-------|-------------|
|attackers| List of IPs used to perfom the attack|
|amplifiers| List of IPs used to perform the attack when amplification attack is detected |
|avg_bps| Attack size bit per second (average)|
|duration_sec| Attack duration in seconds |  
|dns.qry.name| DNS query name | 
|dns.qry.type| DNS query type (A, AAAA, TXT, MX) |
|eth.type| Data link layer protocol used (ethernet/VLAN) | 
|frame.len| Ethernet frame size  | 
|http.request| HTTP request | 
|http.response| HTTP response |
|http.user_agent| HTTP user agent | 
|icmp.type| ICMP type | 
|ip.dst| List of IPs (usually anon) | 
|ip.flags.mf| IP flags | 
|ip.frag_offset| Fragmentation offset | 
|ip.proto| IP protocol | 
|ip.src| List of source IPs (meta field point to `amplifiers` or `attackers`) | 
|ip.ttl| IP TTL |
|key| MD5 hash code |
|key_sha256| SHA256 hash code | 
|multivector_key| SHA256 hash code (index) | 
|ntp.priv.reqcode| NTP request code |
|tags| List of tags (plain text not strutured) | 
|tcp.dstport| TCP destination port | 
|tcp.flags| TCP flags | 
|tcp.srcport| TCP source port | 
|total_dst_ports| Total of destination ports | 
|total_ips| Total of IPs (amplifiers or attackers) | 
|total_packets| Total of packets | 
|udp.dstport| UDP destination port | 
|udp.length| UDP length | 
|udp.srcport| UDP source port | 

