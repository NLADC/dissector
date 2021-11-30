import json
import pandas as pd
from os import PathLike
from enum import Enum
from typing import List, Union, Set, Dict
from datetime import datetime, timedelta
from ipaddr import IPAddress, IPNetwork

from config import Filetype

simple_type = Union[int, str, float, bool]
JSON_compatible = Dict[str, Union[simple_type, List[simple_type]]]


class Tag(Enum):
    ...


class AttackVector:
    """
    Represents one attack vector of a DDoS attack; for example DNS amplification
    """
    df: pd.DataFrame
    fields: JSON_compatible = {}

    def __init__(self, df: pd.DataFrame):
        self.df = df


class Fingerprint:
    """
    Represents the fingerprint of an entire DDoS attack, including generic statistics as well as specific
    attack vectors
    """
    filetype: Filetype  # PCAP or FLOW
    df: pd.DataFrame  # DataFrame with all attack data sent to target
    target_ip: Union[IPAddress, IPNetwork]  # Target IP or network of this attack
    attack_vectors: List[AttackVector] = []  # Attack vector(s) that make up the DDoS attack (e.g. DNS amplification)
    start_time: datetime  # Start time of the DDoS attack
    duration: timedelta  # Duration of the attack in seconds
    total_dst_ports: int  # Total number of ports targeted
    total_packets: int  # Total number of packets sent to target
    total_src_ips: int  # Total number of source IP addresses from which attack traffic originates
    avg_bps: int  # Average number of bytes of attack traffic per second
    ddos_attack_key: str  # Hash digest of the fingerprint
    tags: Set[Tag]  # Set of tags assigned to the DDoS attack, such as Fragmentation, DNS, Amplification, Multi-vector

    def __init__(self, filetpye: Filetype, df: pd.DataFrame):
        """
        Create a fingerprint to which attack vectors can be added.
        Args:
            filetpye: Input file type (PCAP or FLOW)
            df: complete dataframe of the attack filtered only on target IP(-range)
        """
        self.filetype = filetpye
        self.df = df

    def add_attack_vector(self, attack_vector: AttackVector):
        self.attack_vectors.append(attack_vector)

    def save_json(self, destination_path: PathLike):
        ...
