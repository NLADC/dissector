#Resources

| field | description |
|-------|-------------|
|amplifiers| List of IPs used to perform the attack when amplification attack is detected |
|attackers| List of IPs used to perfom the attack|
|avg_bps| Average bit per second |
|duration_sec| Attack duration in seconds |  
|dns.qry.name| DNS query name | 
|dns.qry.type| DNS query type (A, AAAA, TXT, MX) |
|eth.type| Data link layer protocol used (ethernet/VLAN) | 
|frame.len| Ethernet frame size  | 
|http.request| HTTP request | 
|http.response| HTTP response |
|http.user_agent| HTTP User Agent | 
|icmp.type| ICMP type | 
|ip.dst| List of IP addresses (meta field) | 
|ip.flags.mf| IP Flags | 
|ip.frag_offset| Fragmentation Offset
|ip.proto| IP protocol | 
|ip.src| List of SRC IP addresses (meta field) | 
|ip.ttl| IP TTL |
|key| MD5 hash code |
|key_sha256| SHA256 hash code | 
|multivector_key| SHA256 hash code (index)
|ntp.priv.reqcode| NTP Request Code |
|tags| List of tags (plain text not strutured) | 
|tcp.dstport| TCP Destination Port | 
|tcp.flags| TCP Flags | 
|tcp.srcport| TCP Source Port | 
|total_dst_ports| Total of Destination Ports | 
|total_ips| Total of IPs (amplifiers or attackers) | 
|total_packets| Total of packets | 
|udp.dstport| UDP Destination Port | 
|udp.length| UDP Length | 
|udp.srcport| UDP Source Port | 
