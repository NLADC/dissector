import sys
import pandas as pd
from netaddr import IPAddress, IPNetwork
from typing import Any
from collections import defaultdict

from logger import LOGGER
from attack import Attack, AttackVector
from util import get_outliers, FileType

__all__ = ["infer_target", "extract_attack_vectors", "compute_summary"]


def infer_target(attack: Attack) -> IPNetwork:
    """
    Infer the target IP address(es) of this attack.
    If the target is a subnet, this method will homogenize the IP adresses in the attack to the first address in the
    subnet.
    :param attack: Attack object of which to determine the target IP address or network
    :return: Target IP address as an IPNetwork
    """
    LOGGER.debug("Inferring attack target.")
    targets: list[IPAddress] = get_outliers(attack.data,
                                            column='destination_address',
                                            fraction_for_outlier=0.5,
                                            use_zscore=False)
    if len(targets) > 0:
        return IPNetwork(targets[0])

    LOGGER.info('No clear target IP address could be inferred.')
    # Ask the user if the most common destination address (most packets received) is the target
    packets_per_ip = attack.data.groupby('destination_address').nr_packets.sum().sort_values(ascending=False)
    most_traffic_address, nr_packets = list(packets_per_ip.items())[0]
    use_most_common = input(f'The most common destination address is {most_traffic_address} '
                            f'({round(nr_packets / packets_per_ip.sum() * 100, 1)}% of captured packets), '
                            f'is this the target? y/n: ')
    if use_most_common.lower().strip() in ['y', 'yes']:
        return IPNetwork(most_traffic_address)

    LOGGER.info('You can pass a target IP address with the --target flag. '
                'Alternatively, Dissector can look for a target subnet (IPv4/24 or IPv6/64) in case of a carpet '
                'bombing attack.')
    keep_going = input('Continue looking for a target subnet? y/n: ')
    if keep_going.lower().strip() not in ['y', 'yes']:
        LOGGER.info('Aborting.')
        sys.exit()

    # Check for the most targeted IP addresses the fraction of destination IPs that is in their /24 or /64 subnet
    best_network, fraction_ips_in_network = None, 0
    for target in packets_per_ip.keys()[:25]:
        network = IPNetwork(f'{target}/{"24" if target.version == 4 else "64"}')  # /24 (IPv4) or /64 (IPv6) subnet
        frac = packets_per_ip[[x for x in packets_per_ip.keys() if x in network]].sum() / packets_per_ip.sum()
        if frac > fraction_ips_in_network:
            best_network, fraction_ips_in_network = network, frac

    if fraction_ips_in_network > 0.7:
        LOGGER.debug(f'Found an IP subnet that comprises a large fraction of the flows\' destination IPs '
                     f'({round(fraction_ips_in_network, 2)}).')
    else:
        LOGGER.critical('Could not infer a clear target IP address from the data. You can explicitly identify the '
                        'target with the --target flag.')
        use_target = input(f'The most prominent destination IP network is {best_network}, with '
                           f'{round(fraction_ips_in_network * 100, 1)}% of packets. '
                           f'Is this the target of this attack? y/n: ')
        if use_target.lower() not in ['y', 'yes']:
            sys.exit(-1)

    return best_network


def extract_attack_vectors(attack: Attack) -> list[AttackVector]:
    """
    Extract the attack vector(s) that make up this attack, from the Attack object. e.g. DNS amplfication vector
    :param attack: Attack object from which extract vectors
    :return: List of AttackVectors
    """
    LOGGER.info('Extracting attack vectors.')
    # Get (protocol, source_port) outliers including fragmented packets
    with_source_port_0 = get_outliers(attack.data,
                                      column=['protocol', 'source_port'],
                                      fraction_for_outlier=0.05,
                                      use_zscore=False)
    # Get (protocol, source_port) outliers when ignoring fragmented packets
    without_source_port_0 = get_outliers(attack.data[attack.data.source_port != 0],
                                         column=['protocol', 'source_port'],
                                         fraction_for_outlier=0.05,
                                         use_zscore=False)
    protocol_source_port_outliers = list(set(with_source_port_0) | set(without_source_port_0))

    attack_vectors: list[AttackVector] = []
    attack_vector_data = pd.DataFrame()
    fragmentation_protocols = set()  # protocols for which a significant fraction of traffic is fragmented packets

    # Create an attack vector for each source port - protocol pair outlier
    LOGGER.debug(f'Extracting attack vectors from source_port / protocol pair outliers '
                 f'({len(protocol_source_port_outliers)})')
    for protocol, source_port in protocol_source_port_outliers:
        data = attack.data[(attack.data.source_port == source_port) & (attack.data.protocol == protocol)]
        attack_vector_data = pd.concat([attack_vector_data, data])
        if source_port == 0 and protocol in ['UDP', 'TCP']:
            # Don't add fragmented packets as a vector at this stage; it should not count towards the fraction of attack
            fragmentation_protocols.add(protocol)
            continue
        attack_vectors.append(AttackVector(data=data, source_port=source_port, protocol=protocol,
                                           filetype=attack.filetype))

    # See if there is any data left that might be a flood attack on a specific destination port
    if attack_vector_data.empty:
        unallocated_data = attack.data
    else:
        merged_data = attack.data.merge(attack_vector_data.drop_duplicates(), how='left', indicator=True)
        unallocated_data = merged_data[merged_data['_merge'] == 'left_only'].drop('_merge', axis=1)
    protocol_dest_port_outliers = get_outliers(unallocated_data,
                                               column=['protocol', 'destination_port'],
                                               fraction_for_outlier=0.1,
                                               use_zscore=False)
    # remove destination port 0
    protocol_dest_port_outliers = [(proto, port) for proto, port in protocol_dest_port_outliers if port != 0]

    def combine_outliers(port_protocol_tuples: list[tuple[str, int]]) -> list[tuple[str, list[int]]]:
        """
        Combine destination ports in (protocol, destination_port) tuples with the same protocol.
        example: [("UDP", 5), ("UDP", 6), ("TCP", 7)] -> [("UDP", [5, 6]), ("TCP", [7])]
        :param port_protocol_tuples: list of tuples
        :return: port protocol tuples where the destination_ports are combined
        """
        protocol_to_ports = defaultdict(list)
        for proto, port in port_protocol_tuples:
            protocol_to_ports[proto].append(port)
        return list(protocol_to_ports.items())

    protocol_dest_port_outliers = combine_outliers(protocol_dest_port_outliers)
    LOGGER.debug(f"protocol & destination port outliers: {protocol_dest_port_outliers}")
    for protocol, destination_ports in protocol_dest_port_outliers:
        data = unallocated_data[(unallocated_data.destination_port.isin(destination_ports)) &
                                (unallocated_data.protocol == protocol)]
        attack_vector_data = pd.concat([attack_vector_data, data])
        attack_vectors.append(AttackVector(data=data, source_port=-1, protocol=protocol, filetype=attack.filetype))

    # Any remaining attack traffic is likely a flood attack with random source / destination ports
    if attack_vector_data.empty:
        unallocated_data = attack.data
    else:
        merged_data = attack.data.merge(attack_vector_data.drop_duplicates(), how='left', indicator=True)
        unallocated_data = merged_data[merged_data['_merge'] == 'left_only'].drop('_merge', axis=1)
    for protocol in get_outliers(unallocated_data, column='protocol', fraction_for_outlier=0.2):
        LOGGER.debug(f'{protocol} flood attack added to attack vectors')
        data = unallocated_data[(unallocated_data.source_port != 0) & (unallocated_data.protocol == protocol)]
        # random source ports
        attack_vectors.append(AttackVector(data=data, source_port=-1, protocol=protocol, filetype=attack.filetype))

    # Combine attack vectors with the same service and protocol. First create a dictionary grouping them:
    # {(service, protocol): [attack_vectors]}
    vectors_by_service_protocol: dict[tuple[str, str], list[AttackVector]] = defaultdict(list)
    for vector in attack_vectors:
        vectors_by_service_protocol[(vector.service, vector.protocol)].append(vector)

    # Combine attack vectors in the same group by creating a new attack vector with the combined dataframes.
    reduced_vectors: list[AttackVector] = []
    for (service, protocol), vectors in vectors_by_service_protocol.items():
        if len(vectors) > 1:
            reduced_vectors.append(AttackVector(data=pd.concat([v.data for v in vectors]),
                                                source_port=-1, protocol=protocol, filetype=attack.filetype))
        else:
            reduced_vectors.append(vectors[0])
    attack_vectors = reduced_vectors

    # Compute the fraction of all traffic for each attack vector, discard vectors with less than 5% of traffic
    LOGGER.debug('Computing the fraction of traffic each attack vector contributes.')
    while True:
        total_bytes = sum([v.bytes for v in attack_vectors])
        for vector in attack_vectors:
            vector.fraction_of_attack = round(vector.bytes / total_bytes, 3)
            if vector.fraction_of_attack < 0.05:
                break
        else:
            break
        LOGGER.debug(f'removing {vector} ({vector.fraction_of_attack * 100}% of traffic)')
        attack_vectors.remove(vector)

    # Create attack vector(s) with fragmented packets
    for frag_proto in fragmentation_protocols:
        LOGGER.debug(f'Computing {frag_proto} fragmentation vector')
        # Only keep flows in the fragmented packets vector with source IP address that occurs in another attack vector.
        try:
            attack_vector_data = pd.concat([v.data for v in attack_vectors if v.protocol == frag_proto])
            data = attack.data[(attack.data.source_port == 0) & (attack.data.protocol == frag_proto) &
                               attack.data.source_address.isin(attack_vector_data.source_address)]
            attack_vectors.append(AttackVector(data, source_port=0, protocol=frag_proto, filetype=attack.filetype))
        except ValueError:  # No objects to concatenate (attack vector may be previously removed)
            pass

    return sorted(attack_vectors)


def compute_summary(attack_vectors: list[AttackVector]) -> dict[str, Any]:
    """
    Compute the summary statistics of the attack given its attack vectors
    :param attack_vectors: List of attack vectors that make up the attack
    :return: Dictionary with summary statistics
    """
    filetype = attack_vectors[0].filetype
    data = pd.concat([v.data for v in attack_vectors])
    time_start = data.time_start.min()
    time_end = data.time_end.max()
    duration = (time_end - time_start).seconds
    nr_bytes = int(data.nr_bytes.sum())
    nr_packets = int(data.nr_packets.sum())
    return {
        'time_start': str(time_start),
        'time_end': str(time_end),
        'duration_seconds': duration,
        f'total_{"flows" if filetype == FileType.FLOW else "packets"}': len(data),
        'total_megabytes': nr_bytes // 1_000_000,
        'total_packets': nr_packets,
        'total_ips': len(data.source_address.unique()),
        'avg_bps': (nr_bytes << 3) // duration if duration > 0 else 0,  # octets to bits
        'avg_pps': nr_packets // duration if duration > 0 else 0,
        'avg_Bpp': nr_bytes // nr_packets
    }
