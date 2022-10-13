import sys
import pandas as pd
import socket
import os
from enum import Enum
from typing import Union, Any
from pathlib import Path
from configparser import ConfigParser, NoOptionError, NoSectionError

from logger import LOGGER


__all__ = ['IPPROTO_TABLE', 'AMPLIFICATION_SERVICES', 'TCP_FLAG_NAMES', 'TCP_BIT_NUMBERS', 'ETHERNET_TYPES',
           'ICMP_TYPES', 'DNS_QUERY_TYPES', 'FileType', 'determine_filetype', 'print_logo', 'error', 'parse_config',
           'get_outliers']

IPPROTO_TABLE: dict[int, str] = {
    num: name[8:]
    for name, num in vars(socket).items()
    if name.startswith('IPPROTO')
}

AMPLIFICATION_SERVICES: dict[int, str] = {  # UDP port -> service name
    17: 'Quote of the Day',
    19: 'Chargen',
    53: 'DNS',
    69: 'TFTP',
    111: 'TPC',
    123: 'NTP',
    137: 'NetBios',
    161: 'SNMP',
    177: 'XDMCP',
    389: 'LDAP',
    500: 'ISAKMP',
    520: 'RIPv1',
    623: 'IPMI',
    1434: 'MS SQL',
    1900: 'SSDP',
    3283: 'Apple Remote Desktop',
    3389: 'Windows Remote Desktop',
    3702: 'WS-Discovery',
    5093: 'Sentinel',
    5351: 'NAT-PMP',
    5353: 'mDNS',
    5683: 'CoAP',
    10074: 'Mitel MiColab',  # CVE-2022-26143
    11211: 'MEMCACHED',
    27015: 'Steam',
    32414: 'Plex Media',
    33848: 'Jenkins',
    37810: 'DHDiscover'
}

TCP_FLAG_NAMES: dict[str, str] = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RESET',
    'P': 'PUSH',
    'A': 'ACK',
    'U': 'URGENT',
}

TCP_BIT_NUMBERS: dict[int, str] = dict(zip(range(1, 7), TCP_FLAG_NAMES.keys()))

ETHERNET_TYPES: dict[int, str] = {
    0x0800: 'IPv4',
    0x0806: 'ARP',
    0x0842: 'Wake-on-LAN',
    0x22F0: 'Audio Video Transport Protocol (AVTP)',
    0x22F3: 'IETF TRILL Protocol',
    0x22EA: 'Stream Reservation Protocol',
    0x6002: 'DEC MOP RC',
    0x6003: 'DECnet Phase IV, DNA Routing',
    0x6004: 'DEC LAT',
    0x8035: 'Reverse Address Resolution Protocol (RARP)',
    0x809B: 'AppleTalk (Ethertalk)',
    0x80F3: 'AppleTalk Address Resolution Protocol (AARP)',
    0x8100: 'VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility',
    0x8102: 'Simple Loop Prevention Protocol (SLPP)',
    0x8103: 'Virtual Link Aggregation Control Protocol (VLACP)',
    0x8137: 'IPX',
    0x8204: 'QNX Qnet',
    0x86DD: 'IPv6',
    0x8808: 'Ethernet flow control',
    0x8809: 'Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol (LACP)',
    0x8819: 'CobraNet',
    0x8847: 'MPLS unicast',
    0x8848: 'MPLS multicast',
    0x8863: 'PPPoE Discovery Stage',
    0x8864: 'PPPoE Session Stage',
    0x887B: 'HomePlug 1.0 MME',
    0x888E: 'EAP over LAN (IEEE 802.1X)',
    0x8892: 'PROFINET Protocol',
    0x889A: 'HyperSCSI (SCSI over Ethernet)',
    0x88A2: 'ATA over Ethernet',
    0x88A4: 'EtherCAT Protocol',
    0x88A8: 'Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel.',
    0x88AB: 'Ethernet Powerlink[citation needed]',
    0x88B8: 'GOOSE (Generic Object Oriented Substation event)',
    0x88B9: 'GSE (Generic Substation Events) Management Services',
    0x88BA: 'SV (Sampled Value Transmission)',
    0x88BF: 'MikroTik RoMON (unofficial)',
    0x88CC: 'Link Layer Discovery Protocol (LLDP)',
    0x88CD: 'SERCOS III',
    0x88E1: 'HomePlug Green PHY',
    0x88E3: 'Media Redundancy Protocol (IEC62439-2)',
    0x88E5: 'IEEE 802.1AE MAC security (MACsec)',
    0x88E7: 'Provider Backbone Bridges (PBB) (IEEE 802.1ah)',
    0x88F7: 'Precision Time Protocol (PTP) over IEEE 802.3 Ethernet',
    0x88F8: 'NC-SI',
    0x88FB: 'Parallel Redundancy Protocol (PRP)',
    0x8902: 'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)',
    0x8906: 'Fibre Channel over Ethernet (FCoE)',
    0x8914: 'FCoE Initialization Protocol',
    0x8915: 'RDMA over Converged Ethernet (RoCE)',
    0x891D: 'TTEthernet Protocol Control Frame (TTE)',
    0x893a: '1905.1 IEEE Protocol',
    0x892F: 'High-availability Seamless Redundancy (HSR)',
    0x9000: 'Ethernet Configuration Testing Protocol',
    0xF1C1: 'Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)'
}

ICMP_TYPES: dict[int, str] = {
    0: 'Echo Reply',
    3: 'Destination Unreachable',
    5: 'Redirect',
    8: 'Echo',
    9: 'Router Advertisement',
    10: 'Router Solicitation',
    11: 'Time Exceeded',
    12: 'Parameter Problem',
    13: 'Timestamp',
    14: 'Timestamp Reply',
    40: 'Photuris',
    42: 'Extended Echo Request',
    43: 'Extended Echo Reply',
}

DNS_QUERY_TYPES: dict[int, str] = {
    1: 'A',
    28: 'AAAA',
    18: 'AFSDB',
    255: 'ANY',
    42: 'APL',
    257: 'CAA',
    60: 'CDNSKEY',
    59: 'CDS',
    37: 'CERT',
    5: 'CNAME',
    62: 'CSYNC',
    49: 'DHCID',
    32769: 'DLV',
    39: 'DNAME',
    48: 'DNSKEY',
    43: 'DS',
    108: 'EUI48',
    109: 'EUI64',
    13: 'HINFO',
    55: 'HIP',
    65: 'HTTPS',
    45: 'IPSECKEY',
    25: 'KEY',
    36: 'KX',
    29: 'LOC',
    15: 'MX',
    35: 'NAPTR',
    2: 'NS',
    47: 'NSEC',
    50: 'NSEC3',
    51: 'NSEC3PARAM',
    61: 'OPENPGPKEY',
    12: 'PTR',
    46: 'RRSIG',
    17: 'RP',
    24: 'SIG',
    53: 'SMIMEA',
    6: 'SOA',
    33: 'SRV',
    44: 'SSHFP',
    64: 'SVCB',
    32768: 'TA',
    249: 'TKEY',
    52: 'TLSA',
    250: 'TSIG',
    16: 'TXT',
    256: 'URI',
    63: 'ZONEMD'
}


class FileType(Enum):
    """
    PCAP or FLOW traffic capture file options
    """
    FLOW = 'Flow'
    PCAP = 'PCAP'

    def __str__(self):
        return self.value


def determine_filetype(filenames: list[Path]) -> FileType:
    """
    Determine whether the input files are Flows or PCAPs; if it's neither or a mix, quit.
    :param filenames:
    :return: PCAP or FLOW
    """
    filetype = None
    for filename in filenames:
        if not filename.exists() or not filename.is_file() or not os.access(filename, os.R_OK):
            error(f'{filename} does not exist or is not readable. If using docker, did you mount the location '
                  f'as a volume?')

        if filename.suffix.lower() == '.pcap' and filetype in [FileType.PCAP, None]:
            filetype = FileType.PCAP
        elif filename.suffix.lower() == '.nfdump' and filetype in [FileType.FLOW, None]:
            filetype = FileType.FLOW
        else:
            if filetype is None:
                error(f"File extesion '{filename.suffix}' not recognized. "
                      'Please use .pcap for PCAPS and .nfdump for Flows.')
            else:
                error('Please use only one type of capture file to create a fingerprint (.pcap or .nfdump)')
    LOGGER.debug(f'Input file type: {filetype}')
    return filetype if filetype is not None else error('No valid input files given.')


def print_logo() -> None:
    LOGGER.info('''
    ____  _                     __            
   / __ \(_)____________  _____/ /_____  _____
  / / / / / ___/ ___/ _ \/ ___/ __/ __ \/ ___/
 / /_/ / (__  |__  )  __/ /__/ /_/ /_/ / /    
/_____/_/____/____/\___/\___/\__/\____/_/     
''')


def error(message: str):
    LOGGER.error(message)
    sys.exit(-1)


def parse_config(file: Path, misp=False) -> dict[str, Any]:
    """
    Parse the DDoSDB/MISP config file and return host, authorization token, protocol (http/https)
    :param file: Config file (ini format)
    :param misp: Get the MISP credentials instead of DDoS-DB credentials.
    :return: host (str), token (str), protocol (str)
    """
    config = ConfigParser()
    LOGGER.debug(f"Using config file: '{str(file)}'")
    config.read_dict({'ddosdb': {'protocol': 'https'}, 'misp': {'protocol': 'https'}})  # Default protocol
    try:
        with open(file) as f:
            config.read_file(f)
    except FileNotFoundError:
        error("Uploading fingerprint failed. "
              f"Config file '{file}' not found. Provide a config file like ddosdb.ini.example with --config")

    platform = 'misp' if misp else 'ddosdb'
    try:
        if misp:
            return {
                'host': config.get(platform, 'host'),
                'token': config.get(platform, 'token'),
                'protocol': config.get(platform, 'protocol'),
                'sharing_group': config.get(platform, 'sharing_group', fallback=None),
                'publish': config.getboolean(platform, 'publish', fallback=False)
            }
        else:
            return {
                'host': config.get(platform, 'host'),
                'token': config.get(platform, 'token'),
                'protocol': config.get(platform, 'protocol'),
                'shareable': config.getboolean(platform, 'shareable', fallback=False)
            }

    except (NoSectionError, NoOptionError):
        error("Uploading fingerprint failed. "
              f"The config file must include a section '{platform}' with keys 'host' and 'token'.")


def get_outliers(data: pd.DataFrame,
                 column: Union[str, list[str]],
                 fraction_for_outlier: float,
                 use_zscore: bool = True,
                 return_fractions: bool = False,
                 return_others: bool = False) -> list:
    """
    Find the outlier(s) in a pandas DataFrame
    :param data: DataFrame in which to find outlier(s)
    :param column: column or combination of columns in the dataframe for which to find outlier value(s)
    :param fraction_for_outlier: if a value comprises this fraction or more of the data, it is considered an outleir
    :param use_zscore: Also take into account the z-score to determine outliers (> 2 * std from the mean)
    :param return_fractions: Return the fractions of traffic occupied by each outlier.
    :param return_others: in the outliers, return the fraction of "others" - i.e., the non-outlier values combined
    :return:
    """
    packets_per_value = data.groupby(column).nr_packets.sum().sort_values(ascending=False)
    fractions = packets_per_value / packets_per_value.sum()

    zscores = (fractions - fractions.mean()) / fractions.std()
    LOGGER.debug(f"top 5 '{column}':\n{fractions.head()}")

    outliers = [(key, round(fraction, 3)) if return_fractions or return_others else key
                for key, fraction in fractions.items()
                if fraction > fraction_for_outlier or (zscores[key] > 2 and use_zscore)]

    if len(outliers) > 0:
        LOGGER.debug(f"Outlier(s) in column '{column}': {outliers}\n")
        if return_others and (explained := sum([fraction for _, fraction in outliers])) < 0.99:
            outliers.append(('others', round(1 - explained, 3)))
    else:
        LOGGER.debug(f"No outlier found in column '{column}'")
    return outliers
