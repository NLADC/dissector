import shutil
import subprocess
import pandas as pd
import time
from typing import Dict
from pathlib import Path
from io import StringIO

from logger import LOGGER
from util import error, IPPROTO_TABLE, FileType

__all__ = ["read_flow", "read_pcap", "read_file"]

FLOW_COLUMN_NAMES: Dict[str, str] = {
    'ts': "time_start",
    'te': "time_end",
    'pr': "protocol",
    'sa': "source_address",
    'da': "destination_address",
    'sp': "source_port",
    'dp': "destination_port",
    'ipkt': "nr_packets",
    'ibyt': "nr_bytes",
    'flg': "tcp_flags"
}

PCAP_COLUMN_NAMES: Dict[str, str] = {
    'ip.dst': "destination_address",
    'ip.src': "source_address",
    'ip.flags.mf': "ip_flags",
    'tcp.flags': "tcp_flags",
    'ip.proto': "protocol",
    '_ws.col.Destination': "col_destination_address",
    '_ws.col.Source': "col_source_address",
    '_ws.col.Protocol': "service",
    'dns.qry.name': "dns_query_name",
    'dns.qry.type': "dns_query_type",
    'eth.type': "eth_type",
    'frame.len': "nr_bytes",
    'udp.length': "udp_length",
    'http.request.uri': "http_uri",
    'http.request.method': "http_method",
    'http.user_agent': "http_user_agent",
    'icmp.type': "icmp_type",
    'ip.frag_offset': "fragmentation_offset",
    'ip.ttl': "ttl",
    'ntp.priv.reqcode': "ntp_requestcode",
    'tcp.dstport': "tcp_destination_port",
    'tcp.srcport': "tcp_source_port",
    'udp.dstport': "udp_destination_port",
    'udp.srcport': "udp_source_port",
    'frame.time': "time_start"
}


def read_flow(filename: Path) -> pd.DataFrame:
    """
    Load the FLOW capture into a dataframe
    :param filename: location of the FLOW file
    :return: DataFrame of the contents
    """
    # Check if nfdump software is available
    nfdump = shutil.which("nfdump")
    if nfdump is None:
        error("nfdump software not found; it should be on the $PATH. Install from https://github.com/phaag/nfdump")

    command = [nfdump, "-r", str(filename), "-o", "extended", "-o", "csv"]
    LOGGER.info(f'Reading "{filename}"...')
    process = subprocess.run(command, capture_output=True)
    if process.returncode != 0:
        LOGGER.error("nfdump command failed!\n")
        error(f"nfdump command stderr:\n{process.stderr.decode('utf-8')}")
    LOGGER.debug("nfdump finished reading FLOW dump.")

    # Process nfdump output
    LOGGER.info("Loading data into a dataframe.")
    output_buffer = StringIO(process.stdout.decode("utf-8"))
    data: pd.DataFrame = pd.read_csv(output_buffer, encoding="utf8", skipfooter=4, engine='python',
                                     parse_dates=['ts', 'te'])

    # Keep only relevant columns & rename
    data = data[data.columns.intersection(FLOW_COLUMN_NAMES.keys())].rename(columns=FLOW_COLUMN_NAMES)

    LOGGER.debug("Done loading data into dataframe.")
    return data


def read_pcap(filename: Path) -> pd.DataFrame:
    """
    Load the PCAP data into a dataframe
    :param filename: location of the PCAP file
    :return: DataFrame of the contents
    """
    LOGGER.critical(f"Support for PCAPs in this version of dissector is still experimental!")
    time.sleep(2)

    # Check if tshark software is available
    tshark = shutil.which("tshark")
    if not tshark:
        error("Tshark software not found; it should be on the $PATH. Install from https://tshark.dev/")

    LOGGER.info(f'Loading "{filename}"...')

    # Create command
    command = [tshark, "-r", str(filename), "-T", "fields"]
    for field in PCAP_COLUMN_NAMES:
        command.extend(["-e", field])
    for option in ['header=y', 'separator=,', 'quote=d', 'occurrence=f']:
        command.extend(["-E", option])

    process = subprocess.run(command, capture_output=True)
    if process.returncode != 0:
        LOGGER.error("tshark command failed!\n")
        error(f"tshark command stderr:\n{process.stderr.decode('utf-8')}")

    output_buffer = StringIO(process.stdout.decode("utf-8"))
    data: pd.DataFrame = pd.read_csv(output_buffer, parse_dates=['frame.time'])

    # Keep only relevant columns & rename
    data = data[data.columns.intersection(PCAP_COLUMN_NAMES.keys())].rename(columns=PCAP_COLUMN_NAMES)
    print(data.head())

    data['protocol'] = data['protocol'].map(IPPROTO_TABLE)

    # Consolidate fields
    data['source_address'].fillna(data['col_source_address'], inplace=True)
    data['destination_address'].fillna(data['col_destination_address'], inplace=True)
    data.drop(['col_source_address', 'col_destination_address'], axis=1, inplace=True)

    data['source_port'] = data['tcp_source_port'].fillna(data['udp_source_port']).fillna(0)
    data['destination_port'] = data['tcp_destination_port'].fillna(data['udp_destination_port']).fillna(0)
    data.drop(['tcp_source_port', 'udp_source_port', 'tcp_destination_port', 'udp_destination_port'],
              axis=1, inplace=True)
    data['nr_packets'] = 1  # in PCAPs each row is one packet - this allows us to use the FLOW code
    data['time_end'] = data['time_start']  # One packet does not have a duration

    return data


def read_file(filename: Path, filetype: FileType) -> pd.DataFrame:
    """
    Read capture file into Dataframe using either read_flow or read_pcap
    :param filename: Path to capture file
    :param filetype: FLOW or PCAP
    :return: Dataframe with traffic data
    """
    if filetype == FileType.FLOW:
        return read_flow(filename)
    elif filetype == FileType.PCAP:
        return read_pcap(filename)
    else:
        return error("Invalid FileType")

