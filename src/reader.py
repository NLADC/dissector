import os
import shutil
import subprocess
import multiprocessing
import numpy as np
import pandas as pd
import time
from pathlib import Path
from io import StringIO
from netaddr.core import AddrFormatError
from netaddr import IPAddress

from logger import LOGGER
from util import error, IPPROTO_TABLE, FileType, ETHERNET_TYPES, ICMP_TYPES, DNS_QUERY_TYPES

__all__ = ["read_flow", "read_pcap", "read_file"]

FLOW_COLUMN_NAMES: dict[str, str] = {
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

PCAP_COLUMN_NAMES: dict[str, str] = {
    'ip.dst': "destination_address",
    'ip.src': "source_address",
    'tcp.flags': "tcp_flags",
    'ip.proto': "protocol",
    '_ws.col.Destination': "col_destination_address",
    '_ws.col.Source': "col_source_address",
    '_ws.col.Protocol': "service",
    'dns.qry.name': "dns_query_name",
    'dns.qry.type': "dns_query_type",
    'eth.type': "ethernet_type",
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
    process = subprocess.run(command, capture_output=True)
    if process.returncode != 0:
        LOGGER.error("nfdump command failed!\n")
        error(f"nfdump command stderr:\n{process.stderr.decode('utf-8')}")
    LOGGER.debug("nfdump finished reading FLOW dump.")

    # Process nfdump output
    output_buffer = StringIO(process.stdout.decode("utf-8").rsplit('\n', 4)[0])  # Discard summary rows
    LOGGER.info("Loading data into a dataframe.")
    data: pd.DataFrame = pd.read_csv(output_buffer, encoding="utf8", parse_dates=['ts', 'te'])

    # Keep only relevant columns & rename
    data = data[data.columns.intersection(FLOW_COLUMN_NAMES.keys())].rename(columns=FLOW_COLUMN_NAMES)

    LOGGER.debug("Ensuring all columns have the correct data types.")

    data['source_address'] = data['source_address'].apply(IPAddress)
    data['destination_address'] = data['destination_address'].apply(IPAddress)
    data['source_port'] = data['source_port'].astype(np.ushort)
    data['destination_port'] = data['destination_port'].astype(np.ushort)
    data['protocol'] = data['protocol'].astype(str)
    data['tcp_flags'] = data['tcp_flags'].astype(str)
    data['nr_packets'] = data['nr_packets'].astype(int)
    data['nr_bytes'] = data['nr_bytes'].astype(int)

    LOGGER.debug("Done loading data into dataframe.")
    return data


def read_pcap(filename: Path) -> pd.DataFrame:
    """
    Load the PCAP data into a dataframe
    :param filename: location of the PCAP file
    :return: DataFrame of the contents
    """
    # Check if tshark software is available
    tshark = shutil.which("tshark")
    if not tshark:
        error("Tshark software not found; it should be on the $PATH. Install from https://tshark.dev/")

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
    try:
        data: pd.DataFrame = pd.read_csv(output_buffer, parse_dates=['frame.time'], low_memory=False, delimiter=',')
    except pd.errors.ParserError as e:
        LOGGER.info(f'Error reading PCAP file: {e}')
        LOGGER.info(f'Skipping the offending lines...')
        data: pd.DataFrame = pd.read_csv(output_buffer, parse_dates=['frame.time'], low_memory=False, delimiter=',',
                                         on_bad_lines='skip')

    # Keep only relevant columns & rename
    data = data[data.columns.intersection(PCAP_COLUMN_NAMES.keys())].rename(columns=PCAP_COLUMN_NAMES)
    data.dropna(subset=['ethernet_type'], inplace=True)

    LOGGER.debug("Ensuring all columns have the correct data types.")
    # map IP protocol number to name
    data['protocol'] = data['protocol'].map(IPPROTO_TABLE).astype(str)
    # map common EtherType names
    data['ethernet_type'] = data['ethernet_type'].map(lambda r: ETHERNET_TYPES.get(int(str(r), 16), str(r))).astype(str)
    # map ICMP types to their name
    data['icmp_type'] = data['icmp_type'].fillna(-1).map(lambda r: ICMP_TYPES.get(int(r), str(r))).astype(str)
    # map DNS query types to their name
    data['dns_query_type'] = data['dns_query_type'].fillna(-1) \
        .map(lambda r: DNS_QUERY_TYPES.get(int(r), str(r))).astype(str)

    # Consolidate address and port fields, drop rows with invalid IPAddress
    def ip_cast(address):
        try:
            return IPAddress(address)
        except AddrFormatError:
            return np.nan

    data['source_address'] = data['source_address'].fillna(data['col_source_address']).apply(ip_cast)
    data['destination_address'] = data['destination_address'].fillna(data['col_destination_address']).apply(ip_cast)
    data.drop(['col_source_address', 'col_destination_address'], axis=1, inplace=True)
    data.dropna(subset=['source_address', 'destination_address'], inplace=True)

    data['source_port'] = data['tcp_source_port'].fillna(data['udp_source_port']) \
        .fillna(0).astype(np.ushort)
    data['destination_port'] = data['tcp_destination_port'].fillna(data['udp_destination_port']) \
        .fillna(0).astype(np.ushort)
    data.drop(['tcp_source_port', 'udp_source_port', 'tcp_destination_port', 'udp_destination_port'],
              axis=1, inplace=True)

    # Compatibility with FLOW-based methods requires some unavailable fields
    data['nr_packets'] = 1  # in PCAPs each row is one packet - this allows us to use the FLOW code
    data['time_end'] = data['time_start']  # One packet does not have a duration

    # Fill NaN values with reasonable values such that the columns can be cast to an appropriate type
    data['dns_query_name'] = data['dns_query_name'].fillna('').astype(str)
    data['http_uri'] = data['http_uri'].fillna('').astype(str)
    data['http_method'] = data['http_method'].fillna('').astype(str)
    data['http_user_agent'] = data['http_user_agent'].fillna('').astype(str)
    data['fragmentation_offset'] = data['fragmentation_offset'].fillna(0).astype(np.ushort)
    data['ttl'] = data['ttl'].fillna(0).astype(np.uint8)
    data['ntp_requestcode'] = data['ntp_requestcode'].fillna(0).astype(np.uint8)

    return data


def read_file(filename: Path, filetype: FileType, nr_processes: int) -> pd.DataFrame:
    """
    Read capture file into Dataframe using either read_flow or read_pcap
    :param filename: Path to capture file
    :param filetype: FLOW or PCAP
    :param nr_processes: int: number of processes used to concurrently read the capture file.
    :return: Dataframe with traffic data
    """
    LOGGER.info(f'Loading "{filename}"...')

    if filetype == FileType.FLOW:
        return read_flow(filename)
    elif filetype == FileType.PCAP:
        if filename.stat().st_size < (5 ** 6):  # PCAP is smaller than 5MB
            return read_pcap(filename)
        LOGGER.debug(f'Splitting PCAP file {filename} into chunks of 5MB.')
        subprocess.run(['tcpdump', '-r', filename, '-w', '/tmp/dissector_chunk', '-C', '5'], capture_output=True)
        chunks = [Path(rootdir) / file for rootdir, _, files in os.walk('/tmp')
                  for file in files if file.startswith('dissector_chunk')]

        pool = multiprocessing.Pool(nr_processes)
        results = pool.map(read_pcap, chunks)  # Read the PCAP chunks concurrently
        pool.close()
        pool.join()
        for chunk in chunks:
            os.remove(chunk)  # Remove the temporary PCAP chunks from /tmp
        return pd.concat(results)  # Concatenate the partial dataframes
    else:
        return error("Invalid FileType")
