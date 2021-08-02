import sys
import pandas as pd
import netaddr
from typing import Any, List, Tuple

from config import LOGGER


# ----------------------------------------------------------------------------------------------------------------------
def find_outliers(df: pd.DataFrame, field_name: str, fraction_for_outlier: float = 0.8) -> List[Any]:
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

    fractions = df[field_name].value_counts(normalize=True)  # Series: [Fieldname, Normalized count]
    zscores = zscore(fractions)  # Series: [Fieldname, zscore]

    # Most common value comprises more than fraction_for_outlier of values -> outlier
    if fractions[0] > fraction_for_outlier:
        LOGGER.info(f"Outlier in column '{field_name}': {fractions.keys()[0]}")
        return [fractions.keys()[0]]

    # More than 2.5 STDs above the mean -> outlier
    outliers = [field for field in zscores.keys() if zscores[field] > 2.5]
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
    targets: List[str] = find_outliers(df, field_name='ip_dst', fraction_for_outlier=0.7)
    if len(targets) > 0:
        df.ip_dst.loc[targets] = targets[0]  # Homogenize target IPs
        return targets[0], df

    # No outlier foudn: perhaps carpet bombing, look for /24 subnet that fits many target addresses
    def is_public_ip(ip_str: str) -> bool:
        """Helper function returns True if the input IP address is public"""
        try:
            ip_address = netaddr.IPAddress(ip_str)
            return ip_address.is_unicast() and not ip_address.is_private()
        except (ValueError, netaddr.core.AddrFormatError):
            return False

    distribution = df.ip_dst.value_count(normalize=True)  # Series: [IP address, prevalence]
    best_network, fraction_ips_in_network = None, 0
    all_public_ips: pd.Series = distribution.loc[[x for x in df.ip_dst if is_public_ip(x)]]

    # Check for the (max) 50 most targeted IP addresses the fraction of destination IPs that is in their /24 subnet
    for target in all_public_ips.keys()[:50]:
        network = netaddr.IPNetwork(f'{target}/24')  # /24 subnet of target IP
        frac = all_public_ips.loc[[x for x in all_public_ips.keys() if x in network]].sum()
        if frac > fraction_ips_in_network:
            best_network, fraction_ips_in_network = network, frac

    if fraction_ips_in_network > 0.7:
        LOGGER.info(f"Found an IP subnet that comprises a large part of the target IPs, aggregating the IPs.")
        df.ip_dst[df.ip_dst.isin([x for x in all_public_ips.keys() if x in best_network])] = str(best_network[0])
        return str(best_network[0]), df
    else:
        LOGGER.error("Could not infer a target IP address from the data.")
        sys.exit(-1)


# ----------------------------------------------------------------------------------------------------------------------
def infer_attack_vectors(df: pd.DataFrame) -> List[Any]:
    ...
