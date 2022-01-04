import numpy as np
import pandas as pd
import socket
import json
import hashlib
from pathlib import Path
from datetime import datetime
from netaddr import IPAddress, IPNetwork
from typing import Dict, List

from util import get_outliers


class AttackVector:
    def __init__(self, data: pd.DataFrame, source_port: np.uint16, protocol: str):
        self.data = data
        self.source_port = source_port
        self.protocol = protocol.upper()
        self.destination_ports = get_outliers(self.data, 'destination_port', 0.3)[:3]  # top 3 destination ports
        self.packets = self.data.nr_packets.sum()
        self.bytes = self.data.nr_bytes.sum()
        self.time_start: datetime = self.data.time_start.min()
        self.time_end: datetime = self.data.time_end.max()
        self.duration = (self.time_end - self.time_start).seconds
        try:
            assert self.protocol in ["TCP", "UDP"]
            self.service = socket.getservbyport(source_port, protocol.lower()).upper()
        except (AssertionError, OSError):
            if self.source_port == 0 and len(self.destination_ports) == 1 and self.destination_ports[0] == 0:
                self.service = "Fragmented IP packets"
            else:
                self.service = "Unknown service"
        self.source_ips: List[IPAddress] = data.source_address.to_list()
        if self.protocol != "TCP":
            self.tcp_flags = 'N/A'
        else:
            self.tcp_flags = get_outliers(self.data, 'tcp_flags', 0.3)[:3]
        self.source_tos = get_outliers(self.data, 'source_type_of_service', 0.3)[:3]  # top 3 source ToS
        self.destiantion_tos = get_outliers(self.data, 'destination_type_of_service', 0.3)[:3]  # top 3 destination ToS

    def __str__(self):
        return f"[AttackVector] {self.service} on port {self.source_port}, protocol {self.protocol}"

    def __repr__(self):
        return self.__str__()

    def __len__(self):
        return len(self.data)

    def as_dict(self, summarized: bool = False) -> dict:
        return {
            'service': self.service,
            'protocol': self.protocol,
            'source_port': self.source_port,
            'destination_ports': self.destination_ports,
            'TCP_flags': self.tcp_flags,
            'nr_flows': len(self),
            'nr_packets': int(self.packets),
            'nr_bytes': int(self.bytes),
            'time_start': str(self.time_start),
            'time_end': str(self.time_end),
            'duration_seconds': self.duration,
            'source_type_of_service': self.source_tos,
            'destination_type_of_service': self.destiantion_tos,
            'source_ips': f"{len(self.source_ips)} IPs ommitted" if summarized else [str(i) for i in self.source_ips],
        }


class Fingerprint:
    def __init__(self, target: IPNetwork, summary: Dict[str, int], attack_vectors: List[AttackVector]):
        if target.version == 4 and target.prefixlen == 32 or target.version == 6 and target.prefixlen == 128:
            self.target: IPAddress = target.network
        else:
            self.target: IPNetwork = target
        self.summary = summary
        self.attack_vectors = attack_vectors
        self.tags = self.determine_tags()
        self.checksum = hashlib.md5((str(attack_vectors) + str(summary)).encode()).hexdigest()

    def __str__(self):
        return json.dumps(self.as_dict(summarized=True), indent=4)

    def determine_tags(self) -> List[str]:
        tags = []
        if len([v for v in self.attack_vectors if v.service != "Fragmented IP packets"]) > 1:
            tags.append("Multi-vector attack")
        if isinstance(self.target, IPNetwork):
            tags.append("Carpet bombing attack")
        for vector in self.attack_vectors:
            if vector.service == "Fragmented IP packets":
                tags.append("Fragmentation attack")
            elif vector.service in ["DOMAIN", "NTP", "LDAP", "PLEX"]:
                tags.append("Amplification attack")
        return tags

    def write_to_file(self, filename: Path):
        with open(filename, 'w') as file:
            json.dump(self.as_dict(), file)

    def upload_to_ddosdb(self):
        ...  # TODO

    def as_dict(self, anonymous: bool = False, summarized: bool = False) -> dict:
        return {
            'attack_vectors': [av.as_dict(summarized) for av in self.attack_vectors],
            'target': str(self.target) if not anonymous else "Anonymous",
            'tags': self.tags,
            **self.summary,
            'checksum': self.checksum
        }
