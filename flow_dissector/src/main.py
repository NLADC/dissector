from argparse import ArgumentParser, Namespace
from pathlib import Path
from netaddr import IPNetwork

from logger import LOGGER
from reader import read_flow
from attack import Attack
from fingerprint import Fingerprint
from analysis import infer_target, extract_attack_vectors, compute_summary


def parse_arguments() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", type=Path, help="Path to flow capture file", required=True)
    parser.add_argument("--target", type=IPNetwork, help="Optional: target IP address or subnet of this attack")
    parser.add_argument("--debug", action="store_true", help="Optional: show debug messages")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()
    if args.debug:
        LOGGER.setLevel('DEBUG')
    global attack  # For debugging / development purposes only
    global data
    data = read_flow(args.file)
    attack = Attack(data)
    target = args.target or infer_target(attack)
    attack.filter_data_on_target(target_network=target)
    attack_vectors = extract_attack_vectors(attack)
    summary = compute_summary(attack.data)
    fingerprint = Fingerprint(target=target, summary=summary, attack_vectors=attack_vectors)
    print(fingerprint)
    fingerprint.write_to_file(Path('print.json'))
