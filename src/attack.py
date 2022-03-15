import socket
import json
import hashlib
import requests
import urllib3
import pandas as pd
from io import BytesIO
from pathlib import Path
from typing import Dict, List
from functools import total_ordering
from datetime import datetime
from netaddr import IPAddress, IPNetwork

from util import AMPLIFICATION_SERVICES, TCP_FLAG_NAMES, get_outliers, FileType
from logger import LOGGER
from misp import search_misp_events, add_misp_fingerprint

__all__ = ["Attack", "AttackVector", "Fingerprint"]


class Attack:
    def __init__(self, data: pd.DataFrame, filetype: FileType):
        self.data = data
        self.filetype = filetype
        self.attack_vectors: List[AttackVector]

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
    def __init__(self, data: pd.DataFrame, source_port: int, protocol: str, filetype: FileType):
        self.data = data
        self.source_port = source_port
        self.protocol = protocol.upper()
        self.filetype = filetype
        self.destination_ports = dict(get_outliers(self.data,
                                                   'destination_port',
                                                   0.1,
                                                   use_zscore=False,
                                                   return_others=True)) or 'random'
        self.packets = self.data.nr_packets.sum()
        self.bytes = self.data.nr_bytes.sum()
        self.time_start: datetime = self.data.time_start.min()
        self.time_end: datetime = self.data.time_end.max()
        self.duration = (self.time_end - self.time_start).seconds
        self.source_ips: List[IPAddress] = data.source_address.unique()
        self.fraction_of_attack = 0
        try:
            if self.protocol == 'UDP':
                self.service = (AMPLIFICATION_SERVICES.get(self.source_port, None) or
                                socket.getservbyport(source_port, protocol.lower()).upper())
            elif self.protocol == 'TCP':
                self.service = socket.getservbyport(source_port, protocol.lower()).upper()
            else:
                self.service = 'Unknown service'
        except OSError:  # service not found by socket.getservbyport
            if self.source_port == 0 and len(self.destination_ports) == 1 and list(self.destination_ports)[0] == 0:
                self.service = 'Fragmented IP packets'
            else:
                self.service = 'Unknown service'
        except OverflowError:  # Random source port (-1), no specific service
            self.service = None
        if self.protocol == 'TCP':
            self.tcp_flags = dict(get_outliers(self.data, 'tcp_flags', 0.2, return_others=True)) or None
        else:
            self.tcp_flags = None

        if self.filetype == FileType.PCAP:
            self.eth_type = dict(get_outliers(self.data, 'ethernet_type', 0.05, return_others=True)) or 'random'
            self.frame_len = dict(get_outliers(self.data, 'nr_bytes', 0.05, return_others=True)) or 'random'

            if isinstance(self.eth_type, dict) and ('IPv4' in self.eth_type.keys() or 'IPv6' in self.eth_type.keys()):
                # IP packets
                self.frag_offset = dict(get_outliers(self.data, 'fragmentation_offset', fraction_for_outlier=0.1,
                                                     return_others=True)) or 'random'
                self.ttl = dict(get_outliers(self.data, 'ttl', fraction_for_outlier=0.1,
                                             return_others=True)) or 'random'
            if self.service == 'DNS':
                self.dns_query_name = dict(get_outliers(self.data, 'dns_query_name', fraction_for_outlier=0.1,
                                                        return_others=True)) or 'random'
                self.dns_query_type = dict(get_outliers(self.data, 'dns_query_type', fraction_for_outlier=0.1,
                                                        return_others=True)) or 'random'
            elif self.service in ['HTTP', 'HTTPS']:
                self.http_uri = dict(get_outliers(self.data, 'http_uri', fraction_for_outlier=0.05,
                                                  return_others=True)) or 'random'
                self.http_method = dict(get_outliers(self.data, 'http_method', fraction_for_outlier=0.1,
                                                     return_others=True)) or 'random'
                self.http_user_agent = dict(get_outliers(self.data, 'http_user_agent', fraction_for_outlier=0.05,
                                                         return_others=True)) or 'random'
            elif self.service == 'NTP':
                self.ntp_requestcode = dict(get_outliers(self.data, 'ntp_requestcode', fraction_for_outlier=0.1,
                                                         return_others=True)) or 'random'
            elif self.protocol == 'ICMP':
                self.icmp_type = dict(get_outliers(self.data, 'icmp_type', fraction_for_outlier=0.1,
                                                   return_others=True)) or 'random'

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
            f'nr_{"flows" if self.filetype == FileType.FLOW else "packets"}': len(self),
            'nr_packets': int(self.packets),
            'nr_megabytes': int(self.bytes) // 1_000_000,
            'time_start': str(self.time_start),
            'duration_seconds': self.duration,
            'source_ips': f"{len(self.source_ips)} IP addresses ommitted" if summarized
            else [str(i) for i in self.source_ips],
        }
        if self.filetype == FileType.PCAP:
            fields.update({'ethernet_type': self.eth_type,
                           'frame_len': self.frame_len})
            if 'IPv4' in self.eth_type.keys() or 'IPv6' in self.eth_type.keys():  # IP packets
                fields.update({'fragmentation_offset': self.frag_offset,
                               'ttl': self.ttl})
            if self.service == 'DNS':
                fields.update({'dns_query_name': self.dns_query_name,
                               'dns_query_type': self.dns_query_type})
            elif self.service in ['HTTP', 'HTTPS']:
                fields.update({'http_uri': self.http_uri,
                               'http_method': self.http_method,
                               'http_user_agent': self.http_user_agent})
            elif self.service == 'NTP':
                fields.update({'ntp_requestcode': self.ntp_requestcode})
            elif self.protocol == 'ICMP':
                fields.update({'icmp_type': self.icmp_type})
        return fields


class Fingerprint:
    def __init__(self, target: IPNetwork, summary: Dict[str, int], attack_vectors: List[AttackVector],
                 show_target: bool = False):
        if target.version == 4 and target.prefixlen == 32 or target.version == 6 and target.prefixlen == 128:
            self.target: IPAddress = target.network
        else:
            self.target: IPNetwork = target
        self.summary = summary
        self.attack_vectors = attack_vectors
        self.show_target = show_target
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
            json.dump(self.as_dict(anonymous=not self.show_target), file, indent=4)

    def upload_to_ddosdb(self, host: str, token: str, protocol: str = 'https', noverify: bool = False) -> int:
        """
        Upload fingerprint to a DDoS-DB instance
        :param host: hostname of the DDoS-DB instance, without schema (like db.example.com)
        :param token: DDoS-DB Authorization Token
        :param protocol: Protocol to use (http or https)
        :param noverify: (bool) ignore invalid TLS certificate
        :return: HTTP response code
        """
        LOGGER.info(f"Uploading fingerprint to DDoS-DB: {host}")

        fp_json = json.dumps(self.as_dict(anonymous=not self.show_target))
        headers = {
            "Authorization": f"Token {token}"
        }

        try:
            try:
                if noverify:
                    urllib3.disable_warnings()
                r = requests.post(protocol + "://" + host + "/api/fingerprint/",
                                  json=fp_json,
                                  headers=headers,
                                  verify=not noverify)
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
            LOGGER.info(f"Upload success! URL: https://{host}/details?key={self.checksum}")
        else:
            LOGGER.info("Internal Server Error.")
            LOGGER.info("Error Code: {}".format(r.status_code))
        return r.status_code

    def upload_to_misp(self, host: str, token: str, protocol: str = 'https', noverify: bool = False) -> int:
        """
        Upload fingerprint to a MISP instance
        :param host: hostname of the MISP instance, without schema (like misp.example.com)
        :param token: MISP Authorization Token (Auth Key)
        :param protocol: Protocol to use (http or https)
        :param noverify: (bool) ignore invalid TLS certificate
        :return: HTTP response code
        """
        LOGGER.info(f"Uploading fingerprint to MISP: {host}")

        fingerprint = self.as_dict(anonymous=not self.show_target)

        misp_events = None
        filter = {
            "minimal": True,
            "tag": "DDoSCH",
            'eventinfo': fingerprint['key'],
        }
        LOGGER.info(f"Checking if fingerprint {fingerprint['key']} is already present in the MISP")
        try:
            misp_events = search_misp_events(host, token, protocol, noverify, filter)

        except requests.exceptions.SSLError:
            LOGGER.critical(f"SSL Certificate verification of the server {host} failed. To ignore the certificate "
                            f"pass the --noverify flag.")
            LOGGER.info("Fingerprint NOT uploaded")
            return 500

        if misp_events:
            LOGGER.error("The fingerprint already exists.")
            LOGGER.info("Fingerprint NOT uploaded")
            return 500

        add_misp_fingerprint(host, token, protocol, noverify, fingerprint)

        return 201

