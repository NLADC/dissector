import socket
import time
import json
import hashlib
import pytz
import requests
import urllib3
import pprint
from pathlib import Path
from datetime import datetime, timedelta

from util import AMPLIFICATION_SERVICES, ETHERNET_TYPES, DNS_QUERY_TYPES, ICMP_TYPES, TCP_FLAG_NAMES, \
    get_outliers_single, get_outliers_mult, get_ttl_distribution, get_packet_cdf, FileType
from logger import LOGGER
from misp import MispInstance

import duckdb
from duckdb import DuckDBPyConnection

__all__ = ['Attack', 'AttackVector', 'Fingerprint']


class Attack:
    def __init__(self, db: DuckDBPyConnection, view: str, filetype: FileType):
        self.db = db
        self.view = view
        self.filetype = filetype
        # self.attack_vectors: list[AttackVector]
        df = db.execute(f"select count() as entries, sum(nr_packets) as total from '{view}'").fetchdf()
        LOGGER.debug(f"Attack object contains {int(df['entries'][0])} entries, with information on {int(df['total'][0])} packets")

    def filter_data_on_target(self, target: list[str]):
        """
        Only keep traffic directed at the target in Attack.data
        :param target: target network(s) of this attack
        :return: None
        """
        LOGGER.debug('Filtering attack data on target IP address(es).')
        if isinstance(target, str):
            target = [target]

        ip_list = "','".join(target)
        viewid = f"target"
        sql = f"create view '{viewid}' as select * from '{self.view}' where destination_address in ('{ip_list}')"
        LOGGER.debug(sql)
        self.db.execute(sql)
        self.view = viewid
        df = self.db.execute(f"select count() as entries, sum(nr_packets) as total from '{self.view}'").fetchdf()
        LOGGER.debug(f"Attack object contains {int(df['entries'][0])} entries, with information on {int(df['total'][0])} packets")

    def ttl_distribution(self):
        return get_ttl_distribution(self.db, self.view)

    def packet_cdf(self):
        return get_packet_cdf(self.db, self.view)


class AttackVector:
    def __init__(self, db: DuckDBPyConnection, view: str, source_port, protocol: str, filetype: FileType):

        pp = pprint.PrettyPrinter(indent=4)

        # self.data = data
        self.db = db
        self.source_port = source_port
        self.protocol = protocol
        self.filetype = filetype

        self.view = f"{view}_{self.protocol}_{str(source_port)}" if source_port >= 0 \
            else f"{view}_{self.protocol}_min_{str(abs(source_port))}"
        self.input_view = view
        self.input_protocol = protocol
        self.input_source_port = source_port
        start = time.time()
        if source_port  == -1:
            db.execute(
                f"create view '{self.view}' as select * from '{view}' where protocol='{protocol}'")
            self.source_port = \
                dict(get_outliers_single(db, self.view, 'source_port', 0.1, use_zscore=False, return_others=True)) or "random"
        else:
            db.execute(
                f"create view '{self.view}' as select * from '{view}' where protocol='{protocol}' and source_port={source_port}")

        results = db.execute(
            f"select count() as entries, sum(nr_packets) as nr_packets, "
            "sum(nr_bytes) as nr_bytes, min(time_start) as time_start, max(time_end) as time_end "
            f" from '{self.view}'").fetchdf()
        LOGGER.debug(f"\n{results}")
        self.entries = int(results['entries'][0])

        if self.entries == 0:
            return

        self.packets = int(results['nr_packets'][0])
        self.bytes = int(results['nr_bytes'][0])
        self.time_start: datetime = pytz.utc.localize(results['time_start'][0])
        self.time_end: datetime = pytz.utc.localize(results['time_end'][0])
        self.duration = (self.time_end - self.time_start).seconds

        results = db.execute(f"select distinct(source_address) from '{self.view}'").fetchdf()
        self.source_ips = list(results['source_address'])
        LOGGER.debug(f"{len(self.source_ips)} IP Addresses")

        self.destination_ports = \
            dict(get_outliers_single(db, self.view, 'destination_port', 0.1,
                                     use_zscore=False, return_others=True))\
            or "random"
        LOGGER.debug(self.destination_ports)
        self.fraction_of_attack = 0

        try:
            if self.protocol == 'UDP' and source_port != -1:
                self.service = (AMPLIFICATION_SERVICES.get(self.source_port, None) or
                                socket.getservbyport(source_port, self.protocol.lower()).upper())
            elif self.protocol == 'TCP' and source_port != -1:
                self.service = socket.getservbyport(source_port, self.protocol.lower()).upper()
            else:
                self.service = None
        except OSError:  # service not found by socket.getservbyport
            if self.source_port == 0 and len(self.destination_ports) == 1 and list(self.destination_ports)[0] == 0:
                self.service = 'Fragmented IP packets'
            else:
                self.service = None
        except OverflowError:  # Random source port (-1), no specific service
            self.service = None
        LOGGER.debug(f"service: {self.service}")

        self.tcp_flags = None
        if self.protocol == 'TCP':
            tcp_flags = dict(get_outliers_single(db, self.view, 'tcp_flags', 0.1, return_others=True))
            # tcp_flags = dataframe_to_dict(flags['df'], None, others=flags['others'])
            # tcp_flags = dict(flags)

            if tcp_flags:
                self.tcp_flags = {}
                for key, value in tcp_flags.items():
                    self.tcp_flags[key.replace('·', '.')] = value

        if self.filetype == FileType.PCAP:
            self.eth_type = get_outliers_single(db, self.view, 'eth_type', 0.05, return_others=True)
            LOGGER.debug(self.eth_type)
            if self.eth_type:
                et = dict()
                for key, value in self.eth_type:
                    et[ETHERNET_TYPES.get(int(key), "others")] = value
                self.eth_type = et
            LOGGER.debug(f"eth_type: {self.eth_type}\n")

            self.frame_len = dict(get_outliers_single(db, self.view, 'nr_bytes', 0.05, return_others=True)) or "random"
            LOGGER.debug(f"frame_len: {self.frame_len}\n")

            if isinstance(self.eth_type, dict) and ('IPv4' in self.eth_type or 'IPv6' in self.eth_type):
                self.frag_offset = \
                    dict(get_outliers_single(db, self.view, 'fragmentation_offset', 0.1, return_others=True))
                LOGGER.debug(f"frag_offset: {self.frag_offset}\n")

                self.ttl = dict(get_outliers_single(db, self.view, 'ttl', 0.1, return_others=True)) or "random"
                LOGGER.debug(f"ttl: {self.ttl}\n")

            if self.service == 'DNS':
                self.dns_query_name = \
                    dict(get_outliers_single(db, self.view, 'dns_qry_name', 0.1, return_others=True)) or "random"
                LOGGER.debug(f"dns_query_name: {self.dns_query_name}\n")

                self.dns_query_type = \
                    dict(get_outliers_single(db, self.view, 'dns_qry_type', 0.1, return_others=False))
                if self.dns_query_type:
                    dqt = dict()
                    for key, value in self.dns_query_type.items():
                        dqt[DNS_QUERY_TYPES.get(int(key), "others")] = value
                    self.dns_query_type = dqt
                else:
                    self.dns_query_type = "random"
                LOGGER.debug(f"dns_query_type: {self.dns_query_type}\n")

            elif self.protocol == 'ICMP':
                self.icmp_type = \
                    dict(get_outliers_single(db, self.view, 'icmp_type', 0.1, return_others=False)) or None
                if self.icmp_type:
                    icmpt = dict()
                    for key, value in self.icmp_type.items():
                        icmpt[ICMP_TYPES.get(int(key), "others")] = value
                    self.icmp_type = icmpt
                else:
                    self.icmp_type = "random"
                LOGGER.debug(f"icmp_type: {self.icmp_type}\n")

            elif self.service in ['HTTP', 'HTTPS']:
                self.http_uri = \
                    dict(get_outliers_single(db, self.view, 'http_uri', 0.05, return_others=True)) or None
                LOGGER.debug(f"http_uri: {self.http_uri}\n")

                self.http_method = \
                    dict(get_outliers_single(db, self.view, 'http_method', 0.1, return_others=True)) or None
                LOGGER.debug(f"http_method: {self.http_method}\n")

                self.http_user_agent = \
                    dict(get_outliers_single(db, self.view, 'http_user_agent', 0.05, return_others=True)) or None
                LOGGER.debug(f"http_user_agent: {self.http_user_agent}\n")

            elif self.service == 'NTP':
                self.ntp_requestcode = dict(get_outliers_single(
                    db, self.view, 'ntp_requestcode', fraction_for_outlier=0.1, return_others=True)) or 'random'
                LOGGER.debug(f"ntp_requestcode: {self.ntp_requestcode}\n")

    def __str__(self):
        if self.service == 'Fragmented IP packets':
            self.fraction_of_attack = 0
        return f'[AttackVector ({round(self.fraction_of_attack * 100, 1)}% of traffic) {self.protocol}, service: {self.service}]'

    def __repr__(self):
        return self.__str__()

    def __len__(self):
        return int(self.packets)

    def __lt__(self, other):
        if type(other) != AttackVector:
            return NotImplemented
        return self.bytes < other.bytes and self.service != 'Fragmented IP packets'

    def as_dict(self, summarized: bool = False) -> dict:
        fields = {
            'service': self.service,
            'protocol': self.protocol,
            'fraction_of_attack': self.fraction_of_attack if self.service != 'Fragmented IP packets' else None,
            # 'fraction_of_attack': self.fraction_of_attack,
            'source_port': self.source_port if self.source_port != -1 else 'random',
            'destination_ports': self.destination_ports,
            'tcp_flags': self.tcp_flags,
            f'nr_{"flows" if self.filetype == FileType.FLOW else "packets"}': self.entries,
            'nr_packets': int(self.packets),
            'nr_megabytes': int(self.bytes) // 1_000_000,
            'time_start': self.time_start.isoformat(),
            'duration_seconds': self.duration,
            'source_ips': f'{len(self.source_ips)} IP addresses ommitted' if summarized
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

    def summ_nr_pkts(self) -> int:
        return self.packets if self.service != 'Fragmented IP packets' else 0

    def summ_nr_bytes(self) -> int:
        return self.bytes if self.service != 'Fragmented IP packets' else 0

    def targets(self) -> []:
        df = self.db.execute(f"select distinct(destination_address) as targets from '{self.view}'").fetchdf()
        return df['targets'].tolist()

class Fingerprint:
    def __init__(self, target: str, summary: dict[str, int], attack_vectors: list[AttackVector],
                 show_target: bool = False):
        self.target = target
        # If no target is present then this is probably a carpet bombing attack
        # and --carpet argument is given (we wouldn't be here otherwise)
        # Get all IP addresses from the individual attack vectors instead
        if not target:
            av_targets = []
            for av in attack_vectors:
                av_targets += av.targets()
            self.target = sorted(list(set(av_targets)))
        self.summary = summary
        self.attack_vectors = attack_vectors
        self.show_target = show_target
        self.tags = self.determine_tags()
        self.checksum = hashlib.md5((str(attack_vectors) + str(summary)).encode()).hexdigest()

    def __str__(self):
        return json.dumps(self.as_dict(summarized=True, anonymous=not self.show_target), indent=4)

    def as_dict(self, anonymous: bool = False, summarized: bool = False) -> dict:
        return {
            'attack_vectors': [av.as_dict(summarized) for av in self.attack_vectors],
            'target': self.target if not anonymous else f'Anonymized - {len(self.target)} target(s)',
            'tags': self.tags,
            'key': self.checksum,
            **self.summary
        }

    def determine_tags(self) -> list[str]:
        """
        Determine the tags that describe this attack. Characteristics such as "Multi-vector attacK", "UDP flood", etc.
        :return: List of tags (strings)
        """
        tags = []
        if len([v for v in self.attack_vectors if v.service != 'Fragmented IP packets']) > 1:
            tags.append('Multi-vector attack')
        # if isinstance(self.target, IPNetwork):
        #     tags.append('Carpet bombing attack')
        for vector in self.attack_vectors:
            tags.append(vector.protocol)
            if vector.service is None:
                tags.append(f'{vector.protocol} flood attack')
            if vector.protocol == 'TCP':
                if len(vector.tcp_flags) == 1:
                    flags = list(vector.tcp_flags)[0]
                    flag_names = ''
                    for k, v in TCP_FLAG_NAMES.items():
                        if k in flags:
                            flag_names += v + ' '
                    flag_names += 'no flag ' if flag_names == '' else 'flag '
                    tags.append(f'TCP {flag_names}attack')
                else:
                    tags.append('TCP flag attack')
            elif vector.service == 'Fragmented IP packets':
                tags.append('Fragmentation attack')
            elif vector.service in AMPLIFICATION_SERVICES.values():
                tags.append('Amplification attack')
        return list(set(tags))

    def write_to_file(self, filename: Path):
        """
        Save fingerprint as a JSON file to disk
        :param filename: save location
        :return: None
        """
        with open(filename, 'w') as file:
            json.dump(self.as_dict(anonymous=not self.show_target), file, indent=4)

    def upload_to_ddosdb(self,
                         host: str,
                         token: str,
                         protocol: str = 'https',
                         noverify: bool = False,
                         shareable: bool = False) -> int:
        """
        Upload fingerprint to a DDoS-DB instance
        :param host: hostname of the DDoS-DB instance, without schema (like db.example.com)
        :param token: DDoS-DB Authorization Token
        :param protocol: Protocol to use (http or https)
        :param noverify: (bool) ignore invalid TLS certificate
        :param shareable: (bool) allow the DDoS-DB to push fingerprint on to other DDoS-DB instances
        :return: HTTP response code
        """
        LOGGER.info(f'Uploading fingerprint to DDoS-DB: {host}...')

        fp_dict = self.as_dict(anonymous=not self.show_target)
        fp_dict['shareable'] = shareable
        fp_json = json.dumps(fp_dict)
        headers = {
            'Authorization': f'Token {token}'
        }

        try:
            try:
                if noverify:
                    urllib3.disable_warnings()
                r = requests.post(f'{protocol}://{host}/api/fingerprint/',
                                  json=fp_json,
                                  headers=headers,
                                  verify=not noverify)
            except requests.exceptions.SSLError:
                LOGGER.critical(f'SSL Certificate verification of the server {host} failed. To ignore the certificate '
                                f'pass the --noverify flag.')
                LOGGER.info('Fingerprint NOT uploaded to DDoS-DB')
                return 500
        except requests.exceptions.RequestException as e:
            LOGGER.critical('Cannot connect to the DDoS-DB server to upload fingerprint')
            LOGGER.debug(e)
            return 500

        if r.status_code == 403:
            LOGGER.critical('Invalid DDoS-DB credentials or no permission to upload fingerprints.')
        elif r.status_code == 413:
            LOGGER.critical('Fingerprint is too large to upload to this DDoS-DB instance.')
        elif r.status_code == 201:
            LOGGER.info(f'Upload success! URL: {protocol}://{host}/details?key={self.checksum}')
        else:
            LOGGER.critical('DDoS-DB Internal Server Error.')
            LOGGER.critical('Error Code: {}'.format(r.status_code))
            LOGGER.critical('Reason    : {}'.format(r.json()))
        return r.status_code

    def upload_to_misp(self, misp_instance: MispInstance) -> int:
        """
        Upload fingerprint to a MISP instance
        :param misp_instance: MISP instance to which to upload the fingerprint
        :return: HTTP response code
        """
        LOGGER.info(f'Uploading fingerprint to MISP: {misp_instance.host}')

        fingerprint_json = self.as_dict(anonymous=not self.show_target)

        misp_filter = {
            'minimal': True,
            'tag': 'DDoSCH',
            'eventinfo': self.checksum,
        }

        LOGGER.debug(f'Checking if fingerprint {self.checksum} is already present in the MISP')
        try:
            misp_events = misp_instance.search_misp_events(misp_filter)
        except requests.exceptions.SSLError:
            LOGGER.critical(f'SSL Certificate verification of the server {misp_instance.host} failed. '
                            f'To ignore the certificate pass the --noverify flag.')
            LOGGER.info('Fingerprint NOT uploaded.')
            return 500

        if misp_events:
            LOGGER.critical('The fingerprint already exists in this MISP instance.')
            LOGGER.info('Fingerprint NOT uploaded.')
            return 500

        misp_instance.add_misp_fingerprint(fingerprint_json)

        return 201
