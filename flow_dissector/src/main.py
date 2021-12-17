from argparse import ArgumentParser, Namespace
from pathlib import Path
from netaddr import IPNetwork

from logger import LOGGER
from reader import read_flow
from attack import Attack
from fingerprint import Fingerprint
from analysis import infer_target, extract_attack_vectors


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
    # global attack
    data, summary = read_flow(args.file)
    attack = Attack(data, summary)
    target = args.target or infer_target(attack)
    attack.filter_data_on_target(target_network=target)
    attack.attack_vectors = extract_attack_vectors(attack)
    fingerprint = Fingerprint(summary=summary, attack_vectors=attack.attack_vectors)
    fingerprint.write_to_file(Path('print.json'))
