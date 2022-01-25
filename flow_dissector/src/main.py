import pandas as pd
from argparse import ArgumentParser, Namespace
from pathlib import Path
from netaddr import IPNetwork

from logger import LOGGER
from util import parse_config, print_logo
from reader import read_flow
from attack import Attack
from fingerprint import Fingerprint
from analysis import infer_target, extract_attack_vectors, compute_summary


def parse_arguments() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", type=Path, help="Path to flow capture file", required=True)
    parser.add_argument("--output", type=Path, help="Path to directory in which to save the fingerprint.",
                        default=Path('fingerprints'))
    parser.add_argument("--config", type=Path, help="Path to ddosdb config file", default=Path('ddosdb.ini'))
    parser.add_argument("--upload", action="store_true", help="Optional: directly upload fingerprint to DDoSDB")
    parser.add_argument("--noverify", action="store_true", help="Optional: Don't verify DDoSDB's SSL certificates")
    parser.add_argument("--target", type=IPNetwork, help="Optional: target IP address or subnet of this attack")
    parser.add_argument("--debug", action="store_true", help="Optional: show debug messages")
    parser.add_argument("--summary", action="store_true", help="Optional: print fingerprint without source addresses")
    return parser.parse_args()


if __name__ == '__main__':
    print_logo()
    args = parse_arguments()
    if args.debug:
        LOGGER.setLevel('DEBUG')
    # global attack, data, attack_vectors  # for interactive debugging
    data: pd.DataFrame = read_flow(args.file)  # Read the FLOW file into a dataframe
    attack = Attack(data)  # Construct an Attack object with the DDoS data
    target = args.target or infer_target(attack)  # Infer the attack target if not passed as an argument
    attack.filter_data_on_target(target_network=target)  # Keep only the traffic sent to the target
    attack_vectors = extract_attack_vectors(attack)  # Extract the attack vectors from the attack
    summary = compute_summary(attack_vectors)  # Compute summary statistics of the attack (e.g. average bps / Bpp / pps)
    fingerprint = Fingerprint(target=target, summary=summary, attack_vectors=attack_vectors)  # Generate fingeperint

    if args.summary:  # If the user wants a preview, show the finerprint in the terminal
        print(fingerprint)

    args.output.mkdir(parents=True, exist_ok=True)
    fingerprint.write_to_file(args.output / (fingerprint.checksum[:16] + ".json"))  # write the fingerprint to disk

    if args.upload:  # Upload the fingerprint to a specified DDoSDB
        fingerprint.upload_to_ddosdb(*parse_config(args.config), noverify=args.noverify)
