import signal
import sys
import shutil
import subprocess
import socket
import threading
import time
import cursor
import pandas as pd
from typing import Optional, List, Tuple
from subprocess import check_output, CalledProcessError
from queue import Queue
from io import StringIO

from config import LOGGER, Filetype, ctrl_c_handler, QUIET


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
    fields = [
        'dns.qry.type', 'ip.dst', 'ip.flags.mf', 'tcp.flags', 'ip.proto',
        'ip.src', '_ws.col.Destination', '_ws.col.Protocol', '_ws.col.Source',
        'dns.qry.name', 'eth.type', 'frame.len', 'udp.length',
        'http.request', 'http.response', 'http.user_agent', 'icmp.type',
        'ip.frag_offset', 'ip.ttl', 'ntp.priv.reqcode', 'tcp.dstport',
        'tcp.srcport', 'udp.dstport', 'udp.srcport', 'frame.time_epoch',
    ]

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
        None, return value is stored in ret
    """
    nfdump = shutil.which("nfdump")

    if not nfdump:
        LOGGER.error("NFDUMP software not found. It should be on the path.")
        ret.put(None)

    cmd = [nfdump, '-r', filename, '-o', 'extended', '-o', 'json']

    try:
        cmd_stdout = check_output(cmd, stderr=subprocess.DEVNULL)
    except CalledProcessError as e:
        print("nfdump command failed", file=sys.stderr)
        sys.exit(e)

    if not cmd_stdout:
        sys.exit()

    data = StringIO(str(cmd_stdout, 'utf-8'))

    df: pd.DataFrame = pd.read_json(data).fillna(-1)

    # Filter relevant columns
    df = df[['t_first', 't_last', 'proto', 'src4_addr', 'dst4_addr',
             'src_port', 'dst_port', 'fwd_status', 'tcp_flags',
             'src_tos', 'in_packets', 'in_bytes', 'icmp_type',
             'icmp_code',
             ]]
    df = df.rename(columns={'dst4_addr': 'ip_dst',
                            'src4_addr': 'ip_src',
                            'src_port': 'srcport',
                            'dst_port': 'dstport',
                            't_start': 'frame_time_epoch',
                            })
    df.dstport = df.dstport.astype(float).astype(int)
    df.srcport = df.srcport.astype(float).astype(int)

    # convert protocol number to name
    protocol_names = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    df['proto'] = df['proto'].apply(lambda x: protocol_names[x])

    # convert protocol+port to service
    def convert_protocol_service(row):
        try:
            highest_protocol = socket.getservbyport(row['dstport'], row['proto'].lower()).upper()
            return highest_protocol
        except (OSError, OverflowError, TypeError):
            LOGGER.debug(f"Could not resolve service running {row['proto']} at port {row['dstport']}, using 'UNKNOWN'")
            return "UNKNOWN"

    df['highest_protocol'] = df[['dstport', 'proto']].apply(convert_protocol_service, axis=1)
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

    # print(cmd_stdout)
    data = StringIO(str(cmd_stdout))

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
    file_type = file_info.decode("utf-8").split()[1]

    if file_type in ["tcpdump", "pcap", "pcapng", "pcap-ng"]:
        return Filetype.PCAP
    elif file_type == "data" and (b"nfdump" in file_info or b"nfcapd" in file_info):
        return Filetype.FLOW
    else:
        LOGGER.error(file_info)
        LOGGER.warning("Only PCAP or Netflow files are supported.")
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
