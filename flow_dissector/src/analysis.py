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

    LOGGER.info("No clear target IP address could be inferred.")
    # Ask the user if the most common destination address (most packets received) is the target
    packets_per_ip = attack.data.groupby('destination_address').nr_packets.sum().sort_values(ascending=False)
    most_traffic_address, nr_packets = list(packets_per_ip.items())[0]
    use_most_common = input(f"The most common destination address is {most_traffic_address} "
                            f"({round(nr_packets / packets_per_ip.sum() * 100, 1)}% of captured packets), "
                            f"is this the target? y/n: ")
    if use_most_common.lower().strip() in ['y', 'yes']:
        return IPNetwork(most_traffic_address)

    LOGGER.info("You can pass a target IP address with the --target flag. "
                "Alternatively, Dissector can look for a target subnet (IPv4/24 or IPv6/64) in case of a carpet "
                "bombing attack.")
    keep_going = input("Continue looking for a target subnet? y/n: ")
    if keep_going.lower().strip() not in ['y', 'yes']:
        LOGGER.info("Aborting.")
        sys.exit()

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
    port_protocol_outliers = get_outliers(attack.data, column=['source_port', 'protocol'], fraction_for_outlier=0.05,
                                          use_zscore=False)
    LOGGER.debug(f"Attack vectors (source port, protocol): {port_protocol_outliers}")
    attack_vectors: List[AttackVector] = []
    fragmentation_protocols = []
    for port, protocol in port_protocol_outliers:
        if port == 0 and protocol != "ICMP":
            fragmentation_protocols.append(protocol)
            continue
        data = attack.data[(attack.data.source_port == port) & (attack.data.protocol == protocol)]
        attack_vectors.append(AttackVector(data=data, source_port=port, protocol=protocol))
    if len([v for v in attack_vectors if v.service != "Fragmented IP packets"]) == 0:
        protocol = attack.data.protocol.value_counts().keys()[0]
        data = attack.data[(attack.data.source_port != 0) & (attack.data.protocol == protocol)]
        attack_vectors.insert(0, AttackVector(data=data, source_port=-1, protocol=protocol))
    # Compute the fraction of all traffic for each attack vector (except fragmented packets)
    total_packets = sum([v.packets for v in attack_vectors])
    for vector in attack_vectors:
        vector.fraction_of_attack = round(vector.packets / total_packets, 3)
    # Only keep flows in the fragmented packets vector(s) with source IP address that occurs in another attack vector.
    for frag_proto in fragmentation_protocols:
        attack_vector_data = pd.concat([v.data for v in attack_vectors if v.protocol == frag_proto])
        # TODO: Alle source/dest port 0 flows:
        data = attack.data[(attack.data.source_port == 0) & (attack.data.protocol == frag_proto)]
        # TODO: Alleen de source/dest port 0 flows waarvan de source IP ook in een andere vector voorkomt:
        # data = attack.data[(attack.data.source_port == 0) & (attack.data.protocol == frag_proto) &
        #                    attack.data.source_address.isin(attack_vector_data.source_address)]
        attack_vectors.append(AttackVector(data, source_port=0, protocol=frag_proto))

    return sorted(attack_vectors, reverse=True)


def compute_summary(attack_vectors: List[AttackVector]) -> Dict[str, Any]:
    data = pd.concat([v.data for v in attack_vectors])
    time_start = data.time_start.min()
    time_end = data.time_end.max()
    duration = (time_end - time_start).seconds
    nr_bytes = int(data.nr_bytes.sum())
    nr_packets = int(data.nr_packets.sum())
    return {
        "time_start": str(time_start),
        "duration_seconds": duration,
        "total_flows": len(data),
        "total_megabytes": nr_bytes // 1_000_000,
        "total_packets": nr_packets,
        "total_ips": len(data.source_address.unique()),
        "avg_bps": (nr_bytes << 3) // duration,  # // 1_000_000,  # octets to bits # to mbits
        "avg_pps": nr_packets // duration,
        "avg_Bpp": nr_bytes // nr_packets
    }
