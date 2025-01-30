import ipaddress
import os
import time
import duckdb
import pprint
import tempfile

from pathlib import Path
from argparse import ArgumentParser, Namespace

from logger import LOGGER
from misp import MispInstance
from reader import read_files
from attack import Attack, Fingerprint
from analysis import infer_target, extract_attack_vectors, compute_summary
from util import parquet_files_to_view, FileType, determine_filetype, determine_source_filetype, \
    print_logo, parse_config, is_executable_present
from graphs import create_line_graph, create_bar_graph

DOCKERIZED: bool = 'DISSECTOR_DOCKER' in os.environ


def parse_arguments() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument('-f', '--file', type=Path, nargs='+', required=True, dest='files',
                        help='Path to Flow / PCAP file(s)')
    parser.add_argument('--summary', action='store_true',
                        help='Optional: print fingerprint without source addresses')
    # parser.add_argument('-r', action='store_true', help='Optional: use experimental Rust pcap-converter')
    parser.add_argument('--output', type=Path,
                        default=Path('/data/fingerprints') if DOCKERIZED else Path('./fingerprints'),
                        help='Path to directory in which to save the fingerprint '
                            f'(default: {"/data" if DOCKERIZED else "."}/fingerprints)')
    parser.add_argument('--config', type=Path, default=Path('/etc/config.ini'),
                        help='Path to DDoS-DB and/or MISP config file (default: /etc/config.ini)')
    parser.add_argument('--nprocesses', dest='n', type=int, default=os.cpu_count(),
                        help='Number of processes used to read and process PCAPs '
                            f'(default: number of CPU cores ({os.cpu_count()}))')
    parser.add_argument('--target', type=str, dest='target',
                        help='Optional: Specify target IP address of this attack (subnet currently unsupported)')
    parser.add_argument('--carpet', action='store_true',
                        help='Optional: Assume carpet bombing attack if no target can be found')
    parser.add_argument('--ddosdb', action='store_true',
                        help='Optional: Directly upload fingerprint to DDoS-DB')
    parser.add_argument('--misp', action='store_true',
                        help='Optional: Directly upload fingerprint to MISP')
    parser.add_argument('--graph', action='store_true',
                        help='Optional: Create graphs of the attack, stored alongside the fingerprint')
    parser.add_argument('--noverify', action='store_true',
                        help="Optional: Do not verify TLS certificates (accept self-signed certificates)")
    parser.add_argument('--show-target', action='store_true',
                        help='Optional: Do NOT anonymize the target IP address/network in the fingerprint')
    parser.add_argument('--tshark', action='store_true',
                        help='Optional: Force use of tshark/tcpdump over pcap-converter, even if it is present')
    parser.add_argument('--debug', action='store_true',
                        help='Optional: Show debug messages')

    return parser.parse_args()


if __name__ == '__main__':
    pp = pprint.PrettyPrinter(indent=4)

    print_logo()

    args = parse_arguments()
    if args.debug:
        LOGGER.setLevel('DEBUG')

    if args.target:
        try:
            test = ipaddress.ip_address(args.target)
        except Exception as e:
            LOGGER.info("Malformed target specified")
            exit(2)

    filetype = determine_filetype(args.files)

    # Determine which of pcap-converter, tcpdump, tshark or nfdump are installed
    pcap_converter_ok = is_executable_present('pcap-converter')
    tcpdump_ok = is_executable_present('tcpdump')
    tshark_ok = is_executable_present('tshark')
    nfdump_ok = is_executable_present('nfdump')

    # Error out early if one of the required executables (for the specified file type) is not present
    if filetype == FileType.PCAP and args.tshark and not tshark_ok:
        LOGGER.error("Use of tshark requested, but tshark cannot be found. Is it installed properly?")
        exit(1)

    if filetype == FileType.PCAP and args.tshark and not tcpdump_ok:
        LOGGER.error("Use of tshark requested, but tcpdump is needed as well and cannot be found. Is it installed properly?")
        exit(1)

    if filetype == FileType.PCAP and not args.tshark and not pcap_converter_ok and (not tshark_ok or not tcpdump_ok):
        tshark=' nor tshark' if not tshark_ok else ''
        tcpdump=' nor tcpdump' if not tcpdump_ok else ''
        LOGGER.error(f"Pcap file supplied, but neither pcap-converter{tshark}{tcpdump} can be found.")
        LOGGER.error(f"Please ensure that either pcap-converter OR tcpdump and tshark are installed")
        exit(1)

    if filetype == FileType.FLOW and not nfdump_ok:
        LOGGER.error("Flow file supplied, but nfdump cannot be found. Is it installed properly?")
        exit(1)

    start = time.time()
    if filetype == FileType.PQT:
        # If parquet files: check all contain data from either pcap or flow, but not both
        LOGGER.debug("Determine source file type in parquet files")
        fts = [determine_source_filetype(f) for f in args.files]
        ft = set(fts)
        if len(ft) > 1:
            LOGGER.error("More than one source file type in these parquet files")
            exit(1)
        filetype = list(ft)[0]
        LOGGER.debug(f"Original file type is {filetype.value}")
        pqt_files = [str(f) for f in args.files]
    else:
        # Convert the file(s) to parquet
        dst_dir = Path(tempfile.gettempdir()) if DOCKERIZED else Path(f"{os.getcwd()}/parquet")
        pqt_files = read_files(args.files,
                               dst_dir=dst_dir,
                               filetype=filetype,
                               nr_processes=args.n,
                               rust_converter=pcap_converter_ok and not args.tshark)
        duration = time.time()-start
        LOGGER.info(f"Conversion took {duration:.2f}s")
        LOGGER.debug(pqt_files)

    if args.debug and not DOCKERIZED:
        # Store duckdb on disk in debug mode if not dockerized
        os.makedirs('duckdb', exist_ok=True)
        db_name = "duckdb/" + os.path.basename(args.files[0]) + ".duckdb"
        LOGGER.debug(f"Basename: {db_name}")
        if os.path.exists(db_name):
            os.remove(db_name)
        db = duckdb.connect(db_name)
    else:
        # Otherwise just an in-memory database
        db = duckdb.connect()

    # Explicitly set number of threads
    db.execute(f"SET threads={args.n}")

    start = time.time()

    view = parquet_files_to_view(db, pqt_files, filetype)
    attack = Attack(db, view, filetype)

    target = args.target or infer_target(attack)  # Infer attack target if not passed as argument
    LOGGER.debug(target)
    if not target:
        if args.carpet:
            LOGGER.info("No attack targets found, assume carpet bombing attack")
        else:
            LOGGER.info("No attack targets found")
            exit(0)
    else:
        attack.filter_data_on_target(target)
    attack_vectors = extract_attack_vectors(attack)
    if len(attack_vectors) == 0:
        LOGGER.critical(f'No attack vectors found in traffic capture.')
        exit(1)
    summary = compute_summary(attack_vectors)  # Compute summary statistics of the attack (e.g. average bps / Bpp / pps)
    # Generate fingerprint
    fingerprint = Fingerprint(target=target, summary=summary, attack_vectors=attack_vectors,
                              show_target=args.show_target)

    duration = time.time() - start
    LOGGER.info(f"Analysis took {duration:.2f}s")
    if args.summary:  # If the user wants a preview, show the fingerprint in the terminal
        LOGGER.info(str(fingerprint))

    args.output.mkdir(parents=True, exist_ok=True)
    fingerprint.write_to_file(args.output / (fingerprint.checksum[:16] + '.json'))  # write the fingerprint to disk

    if args.graph:
        LOGGER.info("Generating graphs")
        ttl = attack.ttl_distribution()
        create_bar_graph(ttl, 'TTL distribution', max_x=255,
                         filename=args.output / (fingerprint.checksum[:16] + '_ttl'))

        cdf = attack.packet_cdf()
        create_line_graph(cdf, "Cumulative distribution of packets per source", normalize_x=False,
                          filename=args.output / (fingerprint.checksum[:16] + '_cdf'))


    if args.ddosdb:  # Upload the fingerprint to a specified DDoS-DB instance
        fingerprint.upload_to_ddosdb(**parse_config(args.config), noverify=args.noverify)
    if args.misp:  # Upload the fingerprint to a specified MISP instance
        conf = parse_config(args.config, misp=True)
        misp_instance = MispInstance(host=conf['host'], token=conf['token'], protocol=conf['protocol'],
                                     verify_tls=not args.noverify, sharing_group=conf['sharing_group'],
                                     publish=conf['publish'])
        if misp_instance.misp is not None:
            fingerprint.upload_to_misp(misp_instance)

    db.close()
