import socket
import json
import hashlib
import requests
import urllib3
import numpy as np
import pandas as pd
from io import BytesIO
from pathlib import Path
from typing import Dict, List
from functools import total_ordering
from datetime import datetime
from netaddr import IPAddress, IPNetwork

from util import AMPLIFICATION_SERVICES, TCP_FLAG_NAMES, error, get_outliers
from logger import LOGGER

__all__ = ["Attack", "AttackVector", "Fingerprint"]


class Attack:
    def __init__(self, data: pd.DataFrame):
        self.data = data
        self.ensure_datatypes()
        self.attack_vectors: List[AttackVector]

    def ensure_datatypes(self):
        """
        Cast each DataFrame column to the correct type
        :return: None
        """
        LOGGER.debug("Ensuring all columns have the correct data types.")

        def try_cast(colomn_name: str, to_type: type, essential: bool = False) -> None:
            try:
                self.data[colomn_name] = self.data[colomn_name].astype(to_type)
            except KeyError as c:
                LOGGER.critical(f"{str(c).replace('_', ' ')} not in FLOW data")
                if essential:
                    error("Cannot continue with incomplete data")

        try:
            self.data['time_start'] = pd.to_datetime(self.data['time_start'])
            self.data['time_end'] = pd.to_datetime(self.data['time_start'])
        except KeyError as col:
            error(f"{str(col).replace('_', ' ')} not in FLOW data")
        except ValueError:
            error(f"time_start or time_end column cannot be interpreted as datetime")
        try:
            self.data['source_address'] = self.data['source_address'].apply(IPAddress)
            self.data['destination_address'] = self.data['destination_address'].apply(IPAddress)
        except KeyError as col:
            error(f"{str(col).replace('_', ' ')} not in FLOW data")

        try_cast('protocol', to_type=str, essential=True)
        try_cast('source_port', to_type=np.ushort, essential=True)
        try_cast('destination_port', to_type=np.ushort, essential=True)
        try_cast('nr_packets', to_type=int)
        try_cast('nr_bytes', to_type=int)
        try_cast('tcp_flags', to_type=str)

    def filter_data_on_target(self, target_network: IPNetwork):
        """
        Only keep traffic directed at the target in Attack.data
        :param target_network: target network of this attack
        :return: None
        """
        LOGGER.debug("Filtering attack data on target IP address.")
        target_addresses = [x for x in self.data.destination_address if x in target_network]
        self.data = self.data[self.data.destination_address.isin(target_addresses)]


@total_ordering
class AttackVector:
    def __init__(self, data: pd.DataFrame, source_port: int, protocol: str):
        self.data = data
        self.source_port = source_port
        self.protocol = protocol.upper()
        self.destination_ports = dict(get_outliers(self.data,
                                                   'destination_port',
                                                   0.1,
                                                   use_zscore=False,
                                                   return_fractions=True)) or "random"
        self.packets = self.data.nr_packets.sum()
        self.bytes = self.data.nr_bytes.sum()
        self.time_start: datetime = self.data.time_start.min()
        self.time_end: datetime = self.data.time_end.max()
        self.duration = (self.time_end - self.time_start).seconds
        self.source_ips: List[IPAddress] = data.source_address.unique()
        self.fraction_of_attack = 0
        try:
            if self.protocol == "UDP":
                self.service = (AMPLIFICATION_SERVICES.get(self.source_port, None) or
                                socket.getservbyport(source_port, protocol.lower()).upper())
            elif self.protocol == "TCP":
                self.service = socket.getservbyport(source_port, protocol.lower()).upper()
            else:
                self.service = "Unknown service"
        except OSError:  # service not found by socket.getservbyport
            if self.source_port == 0 and len(self.destination_ports) == 1 and list(self.destination_ports)[0] == 0:
                self.service = "Fragmented IP packets"
            else:
                self.service = "Unknown service"
        except OverflowError:  # Random source port (-1), no specific service
            self.service = None
        if self.protocol == "TCP":
            self.tcp_flags = dict(get_outliers(self.data, 'tcp_flags', 0.2, return_fractions=True)) or None
        else:
            self.tcp_flags = None

    def __str__(self):
        return f"[AttackVector] {self.service} on port {self.source_port}, protocol {self.protocol}"

    def __repr__(self):
        return self.__str__()

    def __len__(self):
        return len(self.data)

    def __lt__(self, other):
        if type(other) != AttackVector:
            return NotImplemented
        return self.service == "Fragmented IP packets" or self.bytes < other.bytes

    def as_dict(self, summarized: bool = False) -> dict:
        fields = {
            'service': self.service,
            'protocol': self.protocol,
            'source_port': self.source_port if self.source_port != -1 else "random",
            'fraction_of_attack': self.fraction_of_attack if self.source_port != 0 else None,
            'destination_ports': self.destination_ports,
            'tcp_flags': self.tcp_flags,
            'nr_flows': len(self),
            'nr_packets': int(self.packets),
            'nr_megabytes': int(self.bytes) // 1_000_000,
            'time_start': str(self.time_start),
            'duration_seconds': self.duration,
            'source_ips': f"{len(self.source_ips)} IP addresses ommitted" if summarized
            else [str(i) for i in self.source_ips],
        }
        return fields


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

    def as_dict(self, anonymous: bool = False, summarized: bool = False) -> dict:
        return {
            'attack_vectors': [av.as_dict(summarized) for av in self.attack_vectors],
            'target': str(self.target) if not anonymous else "Anonymous",
            'tags': self.tags,
            'key': self.checksum,
            **self.summary
        }

    def determine_tags(self) -> List[str]:
        """
        Determine the tags that describe this attack. Characteristics such as "Multi-vector attacK", "UDP flood", etc.
        :return: List of tags (strings)
        """
        tags = []
        if len([v for v in self.attack_vectors if v.service != "Fragmented IP packets"]) > 1:
            tags.append("Multi-vector attack")
        if isinstance(self.target, IPNetwork):
            tags.append("Carpet bombing attack")
        for vector in self.attack_vectors:
            tags.append(vector.protocol)
            if vector.service is None:
                tags.append(f"{vector.protocol} flood attack")
            if vector.protocol == "TCP":
                if len(vector.tcp_flags) == 1:
                    flags = list(vector.tcp_flags)[0]
                    flag_names = ""
                    for k, v in TCP_FLAG_NAMES.items():
                        if k in flags:
                            flag_names += v + " "
                    flag_names += "no flag " if flag_names == "" else "flag "
                    tags.append(f"TCP {flag_names}attack")
                else:
                    tags.append("TCP flag attack")
            elif vector.service == "Fragmented IP packets":
                tags.append("Fragmentation attack")
            elif vector.service in AMPLIFICATION_SERVICES.values():
                tags.append("Amplification attack")
        return list(set(tags))

    def write_to_file(self, filename: Path):
        """
        Save fingerprint as a JSON file to disk
        :param filename: save location
        :return: None
        """
        with open(filename, 'w') as file:
            json.dump(self.as_dict(anonymous=True), file)

    def upload_to_ddosdb(self, host: str, username: str, password: str, noverify: bool = False) -> int:
        """
        Upload fingerprint to a DDoS-DB instance
        :param host: hostname of the DDoS-DB instance, without schema (like db.example.com)
        :param username: DDoS-DB username
        :param password: DDoS-DB password
        :param noverify: (bool) ignore invalid TLS certificate
        :return: HTTP response code
        """
        LOGGER.info(f"Uploading fingerprint to DDoS-DB: {host}...")

        files = {"json": BytesIO(json.dumps(self.as_dict(anonymous=True)).encode())}
        headers = {
            "X-Username": username,
            "X-Password": password,
            "X-Filename": self.checksum
        }

        try:
            try:
                urllib3.disable_warnings()
                r = requests.post("https://" + host + "/upload-file", files=files, headers=headers, verify=not noverify)
            except requests.exceptions.SSLError:
                LOGGER.critical(f"SSL Certificate verification of the server {host} failed. To ignore the certificate "
                                f"pass the --noverify flag.")
                LOGGER.info("Fingerprint NOT uploaded")
                return 500
        except requests.exceptions.RequestException as e:
            LOGGER.critical("Cannot connect to the server to upload fingerprint")
            LOGGER.debug(e)
            return 500

        if r.status_code == 403:
            LOGGER.info("Invalid credentials or no permission to upload fingerprints.")
        elif r.status_code == 201:
            LOGGER.info("Upload success!")
            LOGGER.info(f"URL: https://{host}/details?key={self.checksum}")
        else:
            LOGGER.info("Internal Server Error.")
            LOGGER.info("Error Code: {}".format(r.status_code))
        return r.status_code

    def upload_to_misp(self, host: str, username: str, password: str) -> int:
        """
        TODO: upload fingerprint to a MISP instance
        :param host: hostname of the MISP instance, without schema (like misp.example.com)
        :param username: MISP username
        :param password: MISP password
        :return: HTTP response code
        """
        ...
