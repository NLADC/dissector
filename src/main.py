import pandas as pd
from pathlib import Path
from argparse import ArgumentParser, Namespace
from netaddr import IPNetwork

from logger import LOGGER
from util import parse_config, print_logo, determine_filetype
from misp import MispInstance
from reader import read_file
from attack import Attack, Fingerprint
from analysis import infer_target, extract_attack_vectors, compute_summary


def parse_arguments() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", type=Path, help="Path to Flow / PCAP file(s)", nargs="+", required=True,
                        dest="files")
    parser.add_argument("--summary", action="store_true", help="Optional: print fingerprint without source addresses")
    parser.add_argument("--output", type=Path, help="Path to directory in which to save the fingerprint "
                                                    "(default /data-mount/fingerprints)",
                        default=Path('/data/fingerprints'))
    parser.add_argument("--config", type=Path, help="Path to DDoS-DB/MISP config file (default /etc/config.ini)",
                        default=Path('/etc/config.ini'))
    parser.add_argument("--target", type=IPNetwork, help="Optional: target IP address or subnet of this attack")
    parser.add_argument("--ddosdb", action="store_true", help="Optional: directly upload fingerprint to DDoS-DB")
    parser.add_argument("--misp", action="store_true", help="Optional: directly upload fingerprint to MISP")
    parser.add_argument("--noverify", action="store_true", help="Optional: Don't verify TLS certificates")
    parser.add_argument("--debug", action="store_true", help="Optional: show debug messages")
    parser.add_argument("--show-target", action="store_true", help="Optional: Do NOT anonymize the target IP address "
                                                                   "/ network in the fingerprint.")
    return parser.parse_args()


print_logo()
args = parse_arguments()
if args.debug:
    LOGGER.setLevel('DEBUG')

filetype = determine_filetype(args.files)
data: pd.DataFrame = pd.concat([read_file(f, filetype) for f in args.files])  # Read the FLOW file(s) into a dataframe
attack = Attack(data, filetype)  # Construct an Attack object with the DDoS data
target = args.target or infer_target(attack)  # Infer the attack target if not passed as an argument
attack.filter_data_on_target(target_network=target)  # Keep only the traffic sent to the target
attack_vectors = extract_attack_vectors(attack)  # Extract the attack vectors from the attack
summary = compute_summary(attack_vectors)  # Compute summary statistics of the attack (e.g. average bps / Bpp / pps)
# Generate fingeperint
fingerprint = Fingerprint(target=target, summary=summary, attack_vectors=attack_vectors, show_target=args.show_target)

if args.summary:  # If the user wants a preview, show the finerprint in the terminal
    LOGGER.info(str(fingerprint))

args.output.mkdir(parents=True, exist_ok=True)
fingerprint.write_to_file(args.output / (fingerprint.checksum[:16] + ".json"))  # write the fingerprint to disk

if args.ddosdb:  # Upload the fingerprint to a specified DDoS-DB instance
    fingerprint.upload_to_ddosdb(**parse_config(args.config), noverify=args.noverify)
if args.misp:  # Upload the fingerprint to a specified MISP instance
    conf = parse_config(args.config, misp=True)
    misp_instance = MispInstance(host=conf['host'], token=conf['token'], protocol=conf['protocol'],
                                 verify_tls=not args.noverify)
    if misp_instance.misp is not None:
        fingerprint.upload_to_misp(misp_instance)
