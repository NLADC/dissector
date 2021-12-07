import signal
import sys
import shutil
import subprocess
import socket
import threading
import time
import cursor
import pandas as pd
from typing import Optional, List, Tuple, Dict
from subprocess import check_output, CalledProcessError
from queue import Queue
from io import StringIO

from config import LOGGER, Filetype, ctrl_c_handler, QUIET

known_attack_ports: Dict[int, str] = {
    17: "Quote of the Day amplification",
    19: "Chargen amplification",
    25: "SMTP",
    53: "DNS amplification",
    69: "TFTP amplification",
    111: "RPC amplification",
    123: "NTP amplification",
    137: "NetBios amplification",
    161: "SNMP amplification",
    177: "XDMCP amplification",
    389: "LDAP amplification",
    500: "ISAKMP flood",
    520: "RIPv1 amplification",
    623: "IPMI amplification",
    1121: "Memcached",
    1434: "MS SQL monitor amplification",
    1718: "H323",
    1900: "SSDP amplification",
    3283: "Apple Remote Desktop amplification",
    3389: "Windows Remote Desktop",
    3702: "WS-Discovery amplification",
    5093: "Sentinel amplification",
    5351: "NAT-PMP flood",
    5353: "mDNS amplification",
    5683: "CoAP amplification",
    11211: "Memcached amplification",
    27015: "Steam amplification",
    30718: 'IoT Lantronix',
    32414: "Plex Media amplification",
    33848: "Jenkins amplification",
    37810: "DHDiscover amplification",
    47808: 'BACnet',
}


def prepare_tshark_cmd(filename: str) -> Optional[List[str]]:
    """
    Prepare the tshark command that converts a PCAP to a CSV.
    Args:
        filename: path to capture file

    Returns:
        List of command parts
    """

    tshark = shutil.which("tshark")
    if not tshark:
        LOGGER.error("Tshark software not found. It should be on the path.\n")
        return None

    cmd = [tshark, '-r', filename, '-T', 'fields']

    # fields included in the csv
    fields_eth = ['eth.src']  # MAC address
    fields_ip = ['ip.dst', 'ip.flags.mf', 'ip.proto', 'ip.src', 'ip.frag_offset', 'ip.ttl']
    fields_udp = ['udp.dstport', 'udp.srcport', 'udp.length']
    fields_tcp = ['tcp.flags', 'tcp.dstport', 'tcp.srcport', 'tcp.len']
    fields_dns = ['dns.qry.name', 'dns.qry.type']
    fields_columns = ['_ws.col.Destination', '_ws.col.Protocol', '_ws.col.Source']
    fields_http = ['http.request', 'http.response', 'http.user_agent']
    fields_icmp = ['icmp.type', 'icmp.code']
    fields_ntp = ['ntp.priv.reqcode']
    fields_frame = ['frame.len', 'frame.time_epoch']
    fields_ldap = ['ldap.name', 'ldap.requestName']

    fields: List[str] = [*fields_eth, *fields_ip, *fields_udp, *fields_tcp, *fields_dns, *fields_columns, *fields_http,
                         *fields_icmp, *fields_ntp, *fields_frame, *fields_ldap]

    for f in fields:
        cmd.append('-e')
        cmd.append(f)

    # field options
    options = ['header=y', 'separator=,', 'quote=d', 'occurrence=f']
    for o in options:
        cmd.append('-E')
        cmd.append(o)
    return cmd


def flow_to_df(ret: Queue, filename: str) -> None:
    """
    Convert flow file (nfdump) to pandas DataFrame.
    Args:
        ret: Queue object in which to store the return value
        filename: filename

    Returns:
        None, return value is stored in ret (Queue)
    """
    nfdump = shutil.which("nfdump")

    if not nfdump:
        LOGGER.error("NFDUMP software not found. It should be on the path.")
        ret.put(None)
        sys.exit(-1)

    cmd = [nfdump, '-r', filename, '-o', 'extended', '-o', 'json']

    try:
        cmd_stdout = check_output(cmd, stderr=subprocess.DEVNULL)
    except CalledProcessError as e:
        print("nfdump command failed", file=sys.stderr)
        ret.put(None)
        sys.exit(e)

    if not cmd_stdout:
        ret.put(None)
        sys.exit(-1)

    data = StringIO(str(cmd_stdout, 'utf-8'))

    df = pd.read_json(data).fillna(-1)

    LOGGER.debug(f"{len(df)} rows in the DataFrame.")
    # print(df.columns)

    # Filter relevant columns
    df = df[df.columns.intersection(['t_first', 't_last', 'proto', 'src4_addr', 'dst4_addr',
                                     'src6_addr', 'dst6-addr',
                                     'src_port', 'dst_port', 'fwd_status', 'tcp_flags',
                                     'src_tos', 'in_packets', 'in_bytes', 'icmp_type',
                                     'icmp_code',
                                     ])]
    df = df.rename(columns={'dst4_addr': 'ip_dst',
                            'src4_addr': 'ip_src',
                            'src_port': 'srcport',
                            'dst_port': 'dstport',
                            't_start': 'frame_time_epoch',
                            })

    df.dstport = df.dstport.astype(float).astype(int)
    df.srcport = df.srcport.astype(float).astype(int)
    # print(df.in_bytes.value_counts())

    # convert IP protocol number to name
    protocol_names = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    df['proto'] = df['proto'].apply(lambda x: protocol_names[x])

    # convert protocol+port to service
    def convert_protocol_service(port, proto):
        try:
            assert proto in ['udp', 'tcp']
            service = socket.getservbyport(int(port), proto.lower()).upper()
            return service
        except (OSError, OverflowError, TypeError, AssertionError):
            if proto == 'udp':
                return known_attack_ports.get(port, "UNKNOWN")

    protocol_service = {(port, protocol.upper()): convert_protocol_service(int(port), protocol.lower())
                        for port, protocol in df.groupby(['srcport', 'proto']).size().keys()}
    df['service'] = df[['srcport', 'proto']].apply(lambda r: protocol_service[(r.srcport, r.proto)], axis=1)
    # convert to unix epoch (sec)
    df['frame_time_epoch'] = pd.to_datetime(df['t_first']).astype(int) / 10 ** 9
    df = df.drop(['t_last', 't_first', 'fwd_status'], axis=1)

    ret.put(df)


def pcap_to_df(return_value: Queue, filename: str) -> None:
    """
    Convert pcap file to DataFrame structure.
    Args:
        return_value: Queue object in which to store the return value
        filename: filename

    Returns:
        None, return value is stored in ret
    """
    cmd = prepare_tshark_cmd(filename)

    if cmd is None:
        sys.exit()

    try:
        cmd_stdout = check_output(cmd, stderr=subprocess.DEVNULL)
    except CalledProcessError as e:
        print("tshark command failed", file=sys.stderr)
        sys.exit(e)

    if not cmd_stdout:
        print("tshark command failed", file=sys.stderr)
        sys.exit(-1)

    data = StringIO(str(cmd_stdout, 'utf-8'))
    df: pd.DataFrame = pd.read_csv(data, low_memory=False)

    # src/dst port
    if {'tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport'}.issubset(df.columns):
        # Combine source and destination ports from tcp and udp
        df['srcport'] = df['tcp.srcport'].fillna(df['udp.srcport'])
        df['dstport'] = df['tcp.dstport'].fillna(df['udp.dstport'])
        df['dstport'] = df['dstport'].fillna(-1).astype(int)
        df['srcport'] = df['srcport'].fillna(-1).astype(int)

    if {'ip.src', 'ip.dst', '_ws.col.Source', '_ws.col.Destination'}.issubset(df.columns):
        # Combine source and destination IP - works for IPv6
        df['ip.src'] = df['ip.src'].fillna(df['_ws.col.Source'])
        df['ip.dst'] = df['ip.dst'].fillna(df['_ws.col.Destination'])

    # rename protocol field
    df = df.rename({'_ws.col.Protocol': 'highest_protocol'}, axis=1)

    # protocol number to name
    protocol_names = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    df['ip.proto'] = df['ip.proto'].fillna(-1).astype(int)
    df['ip.proto'] = df['ip.proto'].apply(lambda x: protocol_names[x] if (x in protocol_names) else None)

    df['ip.ttl'] = df['ip.ttl'].fillna(-1).astype(int)
    df['udp.length'] = df['udp.length'].fillna(-1).astype(int)
    df['tcp.len'] = df['tcp.len'].fillna(-1).astype(int)
    df['ntp.priv.reqcode'] = df['ntp.priv.reqcode'].fillna(-1).astype(int)

    # timestamp
    try:
        df['start_timestamp'] = df['frame.time_epoch'].iloc[0]
    except IndexError:
        LOGGER.info("Could not find a timestamp.")

    # Remove columns: 'tcp.srcport', 'udp.srcport','tcp.dstport', 'udp.dstport', _ws.col.Source, _ws.col.Destination
    df.drop(['tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport', '_ws.col.Source', '_ws.col.Destination'],
            axis=1, inplace=True)

    # Drop all empty columns (for making the analysis more efficient! less memory.)
    df.dropna(axis=1, how='all', inplace=True)

    df = df.fillna(-1)
    if 'icmp.type' in df.columns:
        df['icmp.type'] = df['icmp.type'].astype(int)

    if 'icmp.code' in df.columns:
        df['icmp.code'] = df['icmp.code'].astype(int)

    if 'dns.qry.type' in df.columns:
        df['dns.qry.type'] = df['dns.qry.type'].astype(int)

    if 'ip.frag_offset' in df.columns:
        df['ip.frag_offset'] = df['ip.frag_offset'].astype(int)

    if 'ip.flags.mf' in df.columns:
        df['ip.flags.mf'] = df['ip.flags.mf'].astype(int)

    if ('ip.flags.mf' in df.columns) and ('ip.frag_offset' in df.columns):
        # Analyse fragmented packets
        df['fragmentation'] = (df['ip.flags.mf'] == 1) | (df['ip.frag_offset'] != 0)
        df.drop(['ip.flags.mf', 'ip.frag_offset'], axis=1, inplace=True)

    df.columns = [c.replace('.', '_') for c in df.columns]

    return_value.put(df)


def determine_file_type(input_file: str) -> Filetype:
    """
    Determine if the input file type is PCAP, flow, or neither.
    Args:
        input_file: path to input traffic capture file

    Returns:
        Filetype
    """

    file_ = shutil.which("file")
    if file_ is None:
        LOGGER.error('"file" command not available; it should be available from $PATH.')
        sys.exit(-1)

    file_info, error = subprocess.Popen([file_, input_file], stdout=subprocess.PIPE).communicate()
    file_type = file_info.decode("utf-8").split(': ')[1]

    if file_type in ["tcpdump", "pcap", "pcapng", "pcap-ng"]:
        return Filetype.PCAP
    elif "data" in file_type or "nfdump" in file_type or "nfcapd" in file_type:
        return Filetype.FLOW
    else:
        LOGGER.error(f"{file_type} --- {file_info}")
        LOGGER.error("Only PCAP or Flow files are supported.")
        sys.exit(-1)


def animated_loading(char_nr: int, msg: str = "loading ") -> None:
    """
    Show loading animation
    Args:
        char_nr: which character to print
        msg: Loading message

    Returns:
        None
    """
    chars = " ▁▂▃▄▅▆▇▇▆▅▄▃▂▁"
    char = chars[int(char_nr / 2) % len(chars)]
    sys.stdout.write('\r' + '[' + char + '] ' + msg)
    time.sleep(.05)
    sys.stdout.flush()


def load_file(filename: str) -> Tuple[Filetype, pd.DataFrame]:
    """
    Load the given traffic capture file as a pandas DataFrame
    Args:
        filename: path to traffic capture file

    Returns:
        Filetype, DataFrame
    """

    file_type = determine_file_type(filename)
    if file_type == Filetype.PCAP:
        loading_function = pcap_to_df
    elif file_type == Filetype.FLOW:
        loading_function = flow_to_df
    else:
        LOGGER.error("Unexpected input filetype! Please provide a PCAP or Netflow file.")
        sys.exit(-1)

    # Load data as pandas DataFrame asynchronously
    return_value = Queue()
    process = threading.Thread(name='process', target=loading_function, args=(return_value, filename))
    process.start()

    # Show loading animation
    msg = f"Loading network file: '{filename}'"
    count = 0
    try:
        cursor.hide()
        while process.is_alive():
            animated_loading(char_nr=count, msg=msg) if not QUIET else time.sleep(.05)
            count += 1
        cursor.show()
        process.join()
    except (KeyboardInterrupt, SystemExit):
        cursor.show()
        ctrl_c_handler(signal.SIGKILL, None)

    df = return_value.get()

    sys.stdout.write('\r' + '[' + '\u2713' + '] ' + msg + '\n')  # Show checkmark in loading animation
    return file_type, df
