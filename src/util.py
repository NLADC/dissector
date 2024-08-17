import datetime
import sys
import pandas as pd
import duckdb
from duckdb import DuckDBPyConnection
import socket
import os
import time
from enum import Enum
from typing import Union, Any
from pathlib import Path
from configparser import ConfigParser, NoOptionError, NoSectionError
from collections import OrderedDict
from typing import Union
import shutil

from logger import LOGGER

import pprint

__all__ = ['IPPROTO_TABLE', 'AMPLIFICATION_SERVICES', 'ETHERNET_TYPES', 'TCP_FLAG_NAMES',
           'ICMP_TYPES', 'DNS_QUERY_TYPES', 'FileType', 'determine_filetype', 'print_logo', 'error', 'parse_config',
           'get_outliers_single', 'get_outliers_mult', 'parquet_files_to_view',
           'determine_source_filetype', 'is_executable_present', 'get_ttl_distribution', 'get_packet_cdf']

IPPROTO_TABLE: OrderedDict() = {
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

INT_COLUMNS: list[str] = [
    'source_port',
    'destination_port',
    'fragmentation_offset',
    'ntp_requestcode',
    'ttl',
    'nr_bytes',
    'nr_packets',
    'icmp_type',
    'eth_type',
]


class FileType(Enum):
    """
    PCAP or FLOW traffic capture file options
    """
    FLOW = 'Flow'
    PCAP = 'PCAP'
    PQT = 'Parquet'

    def __str__(self):
        return self.value


def determine_source_filetype(filename: Path) -> FileType:
    # pcap conversion will have a pcap_file column
    # flow conversion will have a flowsrc column
    filetype = None
    pp = pprint.PrettyPrinter(indent=4)
    db = duckdb.connect()
    db.execute(f"create view test as select * from '{filename}'")
    df = db.execute("describe test").fetchdf()
    db.close()
    if 'flowsrc' in list(df['column_name']):
        filetype = FileType.FLOW
    elif 'pcap_file' in list(df['column_name']):
        filetype = FileType.PCAP
    return filetype


def is_executable_present(executable: str) -> bool:

    if not executable:
        return False

    msg = f"Is executable present? : {executable.ljust(15)} ->"
    # See if we have the executable somewhere on the PATH
    path = shutil.which(executable)
    if path is None:
        LOGGER.debug(f"{msg} No")
    else:
        LOGGER.debug(f"{msg} Yes ({path})")

    return path is not None


def determine_filetype(filenames: list[Path]) -> FileType:
    """
    Determine whether the input files are Flows or PCAPs; if it's neither or a mix, quit.
    :param filenames:
    :return: PCAP or FLOW
    """

    pcapsuffixes = ['.pcap', '.pcapng', '.erf']

    filetype = None
    for filename in filenames:
        if not filename.exists() or not filename.is_file() or not os.access(filename, os.R_OK):
            error(f'{filename} does not exist or is not readable. If using docker, did you mount the location '
                  f'as a volume?')

        if (filename.suffix.lower() in pcapsuffixes or os.path.basename(filename).lower().startswith('snort.log.')) \
                and filetype in [FileType.PCAP, None]:
            filetype = FileType.PCAP
        elif filename.suffix.lower() == '.parquet' and filetype in [FileType.PQT, None]:
            filetype = FileType.PQT
        elif (filename.suffix.lower() == '.nfdump' or filename.name.startswith('nfcapd.')) \
                and filetype in [FileType.FLOW, None]:
            filetype = FileType.FLOW
        else:
            if filetype is None:
                error(f"File extesion '{filename.suffix}' not recognized. "
                      'Please use .pcap or .pcapng for PCAPS and .nfdump or nfcapd. for Flows.')
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


def get_outliers_single(db: DuckDBPyConnection,
                        view: str,
                        column: str,
                        fraction_for_outlier: float,
                        return_others: bool = False,
                        use_zscore=True):
    start = time.time()
    sql = \
        f"select {column}, sum(nr_packets)/(select sum(nr_packets) from '{view}') as frac from '{view}' " \
        f"where {column} is not NULL group by all order by frac desc"

    df_all = db.execute(sql).fetchdf()

    zscores = (df_all['frac'] - df_all['frac'].mean()) / df_all['frac'].std()
    LOGGER.debug(f"top 5 '{column}':\n{df_all.head()}")
    LOGGER.debug(f"{len(df_all)} results")

    outliers = []

    if not df_all.empty:
        # Explicit cast for integer column types (otherwise int turns to float)
        column_type = int if column in INT_COLUMNS else type(df_all.iloc[0][column])

        # If the top result already below fraction and zscore<2 then don't bother
        # (Shaves two seconds of the time needed for traversing 64k destination ports)
        row = df_all.iloc[0]
        if row['frac'] <= fraction_for_outlier and ((use_zscore and zscores[0] <= 2) or not use_zscore):
            outliers = []
        else:
            for index, row in df_all.iterrows():
                if row['frac'] > fraction_for_outlier or (use_zscore and zscores[index] > 2):
                    outliers.append((column_type(row[column]), round(row['frac'], 3)))
                else:
                    # We've iterated to below the threshold, so no need to go on
                    # since results are ordered by descending fraction
                    break

        if outliers and return_others and (explained := sum([fraction for _, fraction in outliers])) < 0.99:
            outliers.append(('others', round(1 - explained, 3)))

    duration = time.time() - start
    LOGGER.debug(f" took {duration:.2f}s")

    return outliers


def get_outliers_mult(db: DuckDBPyConnection,
                      view: str,
                      columns: list[str],
                      fraction_for_outlier: float):
    pp = pprint.PrettyPrinter(indent=4)

    start = time.time()
    cols = ','.join(columns)

    df_all = db.execute(
        f"select {cols}, sum(nr_packets)/(select sum(nr_packets) from '{view}') as frac from '{view}'"
        f" group by all order by frac desc").fetchdf()

    df_frac = df_all[df_all['frac'] > fraction_for_outlier].copy()
    others = None
    df_frac.loc[:, 'frac'] = df_frac['frac'].map(lambda frac: round(frac, 3))

    duration = time.time() - start
    LOGGER.debug(f"{view} --> {columns}({fraction_for_outlier})\n{df_all.head()}")
    LOGGER.debug(f" took {duration:.2f}s")

    return df_frac


def parquet_files_to_view(db: DuckDBPyConnection, pqt_files: list, filetype: FileType) -> str:
    # Create view on parquet file(s)
    db.execute(f"CREATE VIEW raw AS SELECT * FROM read_parquet({pqt_files})")

    if filetype == FileType.FLOW:
        sql = "create view data as select ts as time_start, te as time_end, pr as protocol, " \
              "sa as source_address, da as destination_address, " \
              "sp as source_port, dp as destination_port, " \
              "ipkt as nr_packets, ibyt as nr_bytes, flg as tcp_flags " \
              "from raw"
        LOGGER.debug(sql)
        db.execute(sql)
        return 'data'

    elif filetype == FileType.PCAP:
        # First create a table that can be used to convert ip_proto --> protocol string
        # Below does not work for compiled version of dissector (with nuitka)
        # df_ipproto = pd.DataFrame.from_dict({"ip_proto": IPPROTO_TABLE.keys(), "protocol": IPPROTO_TABLE.values()})
        # db.execute("create table ipproto_table as select * from df_ipproto")
        db.execute("create table ipproto_table (ip_proto INTEGER, protocol VARCHAR);")
        val_list = []
        for k,v in IPPROTO_TABLE.items():
            val_list.append(f"({k},'{v}')")
        sql_str = f"insert into ipproto_table values {','.join(val_list)};"
        db.execute(sql_str)

        # Create a view from that, flattening udp/tcp ports onto one src/dst port (and replacing NaN with 0 as well)
        # Do similar for source/destination address
        sql = "create view data as select " \
              "coalesce(ip_src, col_source) as source_address, " \
              "coalesce(ip_dst, col_destination) as destination_address, " \
              "coalesce(tcp_srcport, udp_srcport, 0) as source_port, " \
              "coalesce(tcp_dstport, udp_dstport, 0) as destination_port, " \
              "coalesce(ip_frag_offset, 0) as fragmentation_offset, " \
              "coalesce(ntp_priv_reqcode, 0) as ntp_requestcode, " \
              "coalesce(ip_ttl, 0) as ttl, " \
              "coalesce(ipproto_table.protocol, col_protocol) as protocol, " \
              "col_protocol as service, " \
              "frame_time as time_start, " \
              "frame_time as time_end, " \
              "frame_len as nr_bytes, " \
              "1 as nr_packets, " \
              "icmp_type, tcp_flags, eth_type, " \
              "dns_qry_name, dns_qry_type, " \
              "http_request_uri as http_uri, " \
              "http_request_method as http_method, http_user_agent " \
              "from raw left join ipproto_table on (raw.ip_proto=ipproto_table.ip_proto)"

        LOGGER.debug(sql)
        db.execute(sql)

        return 'data'


def get_ttl_distribution(db: DuckDBPyConnection,
                         view: str, ) -> pd.DataFrame:
    return db.execute(
        f"select ttl as TTL, 100*count(distinct(source_address))/(select count(distinct(source_address)) "
        f"from '{view}') as 'percentage of data' from '{view}' group by all order by ttl asc"
    ).fetchdf()


def get_packet_cdf(db: DuckDBPyConnection,
                   view: str, ) -> pd.DataFrame:
    part = db.execute(
        f"select source_address, sum(nr_packets) as data from '{view}' group by all order by data asc"
    ).fetchdf()
    part.drop(axis='columns', labels='source_address', inplace=True)
    total = part['data'].sum()
    part['Proportion'] = part.cumsum()
    part['Proportion'] = part['Proportion'] / total
    part.rename(columns={'data': 'number of packets per source', 'Proportion': 'Fraction of data'}, inplace=True)

    return part
