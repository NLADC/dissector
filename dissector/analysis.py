import sys
import pandas as pd
import netaddr
from typing import List, Tuple

from config import LOGGER


# ----------------------------------------------------------------------------------------------------------------------
def get_outliers(df: pd.DataFrame, field_name: str, fraction_for_outlier: float = 0.8) -> list:
    """
    Find the outlier value(s) of a particular column in the DataFrame
    Args:
        df: DataFrame
        field_name: column name for which to find an outlier
        fraction_for_outlier: Fraction of data larger than which a value is determined an outlier

    Returns:
        List with outlier value(s)
    """

    def zscore(x: pd.Series) -> pd.Series:
        """Nr of standard deviations from the mean"""
        return (x - x.mean()) / x.std()

    # TODO: value counts for flows are different (Sample rate)
    fractions = df[field_name].value_counts(normalize=True)  # Series: [Fieldname, Normalized count]
    if fractions.values[10:].sum() > 0.5:
        LOGGER.debug(f"No outlier found in column '{field_name}'")
        return []

    zscores = zscore(fractions)  # Series: [Fieldname, zscore]
    # More than 2 STDs above the mean or more than 80% of data -> outlier
    outliers = [key for key in zscores.keys() if zscores[key] > 2 or fractions[key] > fraction_for_outlier]
    if len(outliers) > 0:
        LOGGER.info(f"Outlier(s) in column '{field_name}': {outliers}")
    else:
        LOGGER.info(f"No outlier found in column '{field_name}'")
    return outliers


# ----------------------------------------------------------------------------------------------------------------------
def infer_target(df: pd.DataFrame) -> Tuple[str, pd.DataFrame]:
    """
    Infer the target IP address(es) of the attack described by the given dataframe
    Args:
        df: attack data

    Returns:
        Target IP as string, DataFrame with homogenized IP addresses if the target is a subnet (first IP in the subnet)
    """
    targets: List[str] = get_outliers(df, field_name='ip_dst', fraction_for_outlier=0.7)
    if len(targets) > 0:
        df.loc[df.ip_dst.isin(targets), 'ip_dst'] = targets[0]  # Homogenize target IPs
        return targets[0], df

    # No outlier found: perhaps carpet bombing, look for /24 subnet that fits many target addresses
    def is_public_ip(ip_str: str) -> bool:
        """Helper function returns True if the input IP address is public"""
        try:
            ip_address = netaddr.IPAddress(ip_str)
            return ip_address.is_unicast() and not ip_address.is_private()
        except (ValueError, netaddr.core.AddrFormatError):
            return False

    distribution = df.ip_dst.value_counts(normalize=True)  # Series: [IP address, prevalence]
    best_network, fraction_ips_in_network = None, 0
    all_public_ips: pd.Series = distribution.loc[[x for x in df.ip_dst if is_public_ip(x)]]

    # Check for the most targeted IP addresses the fraction of destination IPs that is in their /24 subnet
    for target in all_public_ips.keys()[:10]:
        network = netaddr.IPNetwork(f'{target}/24')  # /24 subnet of target IP
        frac = all_public_ips.loc[[x for x in all_public_ips.keys() if x in network]].sum()
        if frac > fraction_ips_in_network:
            best_network, fraction_ips_in_network = network, frac

    if fraction_ips_in_network > 0.7:
        LOGGER.info(f"Found an IP subnet that comprises a large part of the target IPs, homogenizing the IPs.")
        ips_in_subnet = [ip for ip in all_public_ips.keys() if ip in best_network]
        df.loc[df.ip_dst.isin(ips_in_subnet), 'ip_dst'] = str(best_network[0])
        return str(best_network[0]), df
    else:
        LOGGER.error("Could not infer a target IP address from the data.")
        sys.exit(-1)


# ----------------------------------------------------------------------------------------------------------------------
def infer_attack_vectors(df: pd.DataFrame) -> List[pd.DataFrame]:
    """
    Infer the attack vector(s) in the attack described by the given dataframe. One attack verctor per protocol used.
    Args:
        df: DataFrame with attack data

    Returns:
        List of DataFrames, each describing one attack vector.
    """
    protocol_outliers = get_outliers(df, field_name='highest_protocol')

    vectors = [df[df.highest_protocol == protocol] for protocol in protocol_outliers]

    # IPv4 or IPv6 as highest protocol usually denotes a fragmentation attack. Fragmented packets are raw IP packets
    # without other headers. The following looks at the remaining packets to determine the vector with packet headers.
    if len(protocol_outliers) == 1 and protocol_outliers[0].lower() in ['ipv4', 'ipv6']:
        vectors.extend(infer_attack_vectors(df[~df.highest_protocol.isin(['IPv4', 'IPv6'])]))

    return vectors


# ----------------------------------------------------------------------------------------------------------------------
# def get_mac_vendors(mac_addresses: pd.Series) -> Dict[str, float]:
#     """
#     This appears to not be very useful, since routers alter the source MAC address when forwarding the packet.
#     Get the most common MAC address vendors (and their contribution to the traffic) from the Ethernet frames
#     Args:
#         mac_addresses: eth_src column of the attack DataFrame
#
#     Returns:
#         dict: {vendor name: fraction of traffic}
#     """
#     LOGGER.info(f"Looking up and aggregating MAC Address vendors.")
#     prefix_3 = mac_addresses.apply(lambda address: ':'.join(address.split(':')[:3]))
#     fractions = prefix_3.value_counts(normalize=True)
#     vendor_fractions: Dict[str, float] = {}
#     for mac_prefix in fractions.keys()[:50]:
#         try:
#             resp = requests.get(f"https://api.macvendors.com/{mac_prefix}", timeout=4)
#         except requests.RequestException:
#             continue
#         try:
#             resp.raise_for_status()
#         except requests.HTTPError:
#             continue
#         vendor = resp.text
#         if vendor == 'IEEE Registration Authority':  # Unknown or too small MAC prefix
#             continue
#         vendor_fractions[vendor] = vendor_fractions.get(vendor, 0) + fractions[mac_prefix]
#
#     return vendor_fractions


# ----------------------------------------------------------------------------------------------------------------------
def generate_fingerprint(vector: pd.DataFrame) -> dict:
    """
    Generate a fingerprint of the given attack vector (DataFrame).
    The fingerprint contains the outliers of the various fields.
    Args:
        vector: The attack vector

    Returns:
        Fingerprint (dictionary)
    """
    ignore_columns = ['ip_src', 'start_timestamp', 'eth_src']
    fingerprint = {'ip_src': list(vector.ip_src.unique()),
                   'nr_packets': len(vector)}
    for key in vector:
        if key in ignore_columns:
            continue
        if (outliers := get_outliers(vector, key)) not in ([], [-1]):
            LOGGER.debug(f"Found outlier for {key}, adding to fingerprint.")
            fingerprint[key] = outliers
    return fingerprint
