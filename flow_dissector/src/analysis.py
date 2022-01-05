import sys
import pandas as pd
from netaddr import IPAddress, IPNetwork
from typing import List, Dict, Any
from logger import LOGGER
from attack import Attack
from fingerprint import AttackVector
from util import get_outliers

__all__ = ['infer_target', 'extract_attack_vectors', 'compute_summary']


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
                                            fraction_for_outlier=0.5,
                                            use_zscore=False)
    if len(targets) > 0:
        return IPNetwork(targets[0])

    LOGGER.info("No clear target IP address could be inferred. "
                "You can pass a target IP address with the --target flag. "
                "Alternatively, Dissector can look for a target subnet (IPv4/24 or IPv6/64) in case of a carpet "
                "bombing attack.")
    keep_going = input("Continue looking for a target subnet? y/n: ")
    if keep_going.lower().strip() not in ['y', 'yes']:
        LOGGER.info("Aborting.")
        sys.exit()

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

    return best_network


def extract_attack_vectors(attack: Attack) -> List[AttackVector]:
    port_protocol_outliers = get_outliers(attack.data, column=['source_port', 'protocol'], fraction_for_outlier=0.1,
                                          use_zscore=False)
    LOGGER.debug(f"Attack vectors (source port, protocol): {port_protocol_outliers}")
    attack_vectors: List[AttackVector] = []
    for port, protocol in port_protocol_outliers:
        data = attack.data[(attack.data.source_port == port) & (attack.data.protocol == protocol)]
        attack_vectors.append(AttackVector(data=data, source_port=port, protocol=protocol))
    if len([v for v in attack_vectors if v.service != "Fragmented IP packets"]) == 0:
        protocol = attack.data.protocol.value_counts().keys()[0]
        data = attack.data[(attack.data.source_port != 0) & (attack.data.protocol == protocol)]
        attack_vectors.insert(0, AttackVector(data=data, source_port=-1, protocol=protocol))
    return attack_vectors


def compute_summary(data: pd.DataFrame) -> Dict[str, Any]:
    time_start = data.time_start.min()
    time_end = data.time_end.max()
    duration = (time_end - time_start).seconds
    nr_bytes = int(data.nr_bytes.sum())
    nr_packets = int(data.nr_packets.sum())
    return {
        "time_start": str(time_start),
        "duration_seconds": duration,
        "nr_flows": len(data),
        "nr_megabytes": nr_bytes // 1_000_000,
        "nr_packets": nr_packets,
        "total_ips": len(data.source_address.unique()),
        "average_mbps": (nr_bytes << 3) // duration // 1_000_000,  # octets to bits to mbits
        "average_pps": nr_packets // duration,
        "average_Bpp": nr_bytes // nr_packets
    }
