import numpy as np
import pandas as pd
import socket
import json
from pathlib import Path
from netaddr import IPAddress
from typing import Dict, List

from util import get_outliers


class AttackVector:
    def __init__(self, data: pd.DataFrame, source_port: np.uint16, protocol: str):
        self.data = data
        self.source_port = source_port
        self.protocol = protocol
        try:
            assert protocol.lower() in ['tcp', 'udp']
            self.service = socket.getservbyport(source_port, protocol.lower())
        except (AssertionError, OSError):
            self.service = 'Unknown service'
        self.source_ips: List[IPAddress] = data.source_address.to_list()
        # TODO outliers for other keys

    def __str__(self):
        return f"[AttackVector] {self.service} on port {self.source_port}, protocol {self.protocol}"

    def __repr__(self):
        return self.__str__()

    def as_dict(self) -> dict:
        return {
            'service': self.service,
            'protocol': self.protocol,
            'source_port': self.source_port,
            'source_ips': [str(i) for i in self.source_ips],  # FIXME use custom JSON Encoder
        }


class Fingerprint:
    def __init__(self, summary: Dict[str, int], attack_vectors: List[AttackVector]):
        self.summary = summary
        self.attack_vectors = attack_vectors

    def __str__(self):
        return f"[Fingerprint]"  # TODO

    def determine_tags(self):
        ... # TODO

    def write_to_file(self, filename: Path):
        with open(filename, 'w') as file:
            json.dump(self.as_dict(), file)

    def upload_to_ddosdb(self):
        ...  # TODO

    def anonymize(self):
        ...  # TODO

    def as_dict(self, anonymous: bool = False, summarized: bool = False) -> dict:
        return {
            'attack_vectors': [av.as_dict() for av in self.attack_vectors],
            **self.summary
        }
    # TODO use anonymous and summarized
