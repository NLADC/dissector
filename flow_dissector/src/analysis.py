import sys
from netaddr import IPAddress, IPNetwork
from typing import List

from logger import LOGGER
from attack import Attack
from fingerprint import AttackVector
from util import get_outliers


def infer_target(attack: Attack) -> IPNetwork:
    """
    Infer the target IP address(es) of this attack.
    If the target is a subnet, this method will homogenize the IP adresses in the attack to the first address in the
    subnet.
    :param attack: Attack object of which to determine the target IP address or network
    :return: Target IP address
    """
    targets: List[IPAddress] = get_outliers(attack.data,
                                            column='destination_address',
                                            fraction_for_outlier=0.7,
                                            use_zscore=False)
    if len(targets) > 0:
        return IPNetwork(targets[0])

    # nr of packets per IP adres, sorted (descending)
    packets_per_ip = attack.data.groupby('destination_address').nr_packets.sum().sort_values(ascending=False)

    # Check for the most targeted IP addresses the fraction of destination IPs that is in their /24 or /64 subnet
    best_network, fraction_ips_in_network = None, 0
    for target in packets_per_ip.keys()[:25]:
        network = IPNetwork(f'{target}/{"24" if target.version == 4 else "64"}')  # /24 (IPv4) or /64 (IPv6) subnet
        frac = packets_per_ip[[x for x in packets_per_ip.keys() if x in network]].sum() / packets_per_ip.sum()
        if frac > fraction_ips_in_network:
            best_network, fraction_ips_in_network = network, frac

    if fraction_ips_in_network > 0.7:
        LOGGER.debug(f"Found an IP subnet that comprises a large fraction of the flows' destination IPs "
                     f"({round(fraction_ips_in_network, 2)}).")
    else:
        LOGGER.critical("Could not infer a clear target IP address from the data. You can explicitly identify the "
                        "target with the --target flag.")
        use_target = input(f"The most prominent destination IP network is {best_network}, with "
                           f"{round(fraction_ips_in_network * 100, 1)}% of packets. "
                           f"Is this the target of this attack? y/n: ")
        if use_target.lower() not in ['y', 'yes']:
            sys.exit(-1)

    # ips_in_subnet = [ip for ip in packets_per_ip.keys() if ip in best_network]
    # attack.data.loc[attack.data.destination_address.isin(ips_in_subnet), 'destination_address'] = str(best_network[0])
    return best_network


def extract_attack_vectors(attack: Attack) -> List[AttackVector]:
    port_protocol_outliers = get_outliers(attack.data, column=['source_port', 'protocol'], fraction_for_outlier=0.10)
    LOGGER.debug(f"Attack vectors (source port, protocol): {port_protocol_outliers}")
    attack_vectors: List[AttackVector] = []
    for port, protocol in port_protocol_outliers:
        data = attack.data[(attack.data.source_port == port) & (attack.data.protocol == protocol)]
        attack_vectors.append(AttackVector(data=data, source_port=port, protocol=protocol))
    return attack_vectors
