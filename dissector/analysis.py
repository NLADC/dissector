import sys
import pandas as pd
import netaddr
from typing import Any, Optional, Tuple

from config import LOGGER


# ----------------------------------------------------------------------------------------------------------------------
def find_outlier(df: pd.DataFrame, field_name: str) -> Optional[Any]:
    """
    Find the outlier value of a particular column in the DataFrame
    Args:
        df: DataFrame
        field_name: column name for which to find an outlier

    Returns:
        Outlier or None
    """
    distribution = df[field_name].value_counts(normalize=True)
    if distribution[0] > 0.8:  # > 80% of values -> outlier
        return distribution.keys()[0]
    return None


# ----------------------------------------------------------------------------------------------------------------------
def infer_target(df: pd.DataFrame) -> Tuple[str, pd.DataFrame]:
    """
    Infer the target IP address(es) of the attack described by the given dataframe
    Args:
        df: attack data

    Returns:
        Target IP as string, DataFrame with homogenized IP addresses if the target is a subnet (first IP in the subnet)
    """
    distribution: pd.Series = df['ip_dst'].value_counts(normalize=True)
    assert len(distribution) > 0, "Could not find a target IP in the given data."
    if distribution[0] > 0.7:
        LOGGER.info(f"Found a single outlier target IP: {distribution.keys()[0]} ({round(distribution[0]*100, 1)}%).")
        return distribution.keys()[0], df

    # No outlier, perhaps carpet bombing, look for /24 subnet that fits many target addresses
    def is_public_ip(ip_str: str) -> bool:
        try:
            ip_address = netaddr.IPAddress(ip_str)
            return ip_address.is_unicast() and not ip_address.is_private()
        except (ValueError, netaddr.core.AddrFormatError):
            return False

    best_net, fraction_ips_in_network = None, 0
    # Check for the (max) 50 most targeted IP addresses the fraction of destination IPs that is in their /24 subnet
    all_public_ips: pd.Series = distribution.loc[[x for x in df.ip_dst if is_public_ip(x)]]
    for target in all_public_ips.keys()[:50]:
        ip_net = netaddr.IPNetwork(f'{target}/24')  # /24 subnet of target IP
        frac = all_public_ips.loc[[x for x in all_public_ips.keys() if x in ip_net]].sum()
        if frac > fraction_ips_in_network:
            best_net, fraction_ips_in_network = ip_net, frac

    if fraction_ips_in_network > 0.7:
        LOGGER.info(f"Found an IP subnet that comprises a large part of the target IPs, aggregating the IPs.")
        df.ip_dst[df.ip_dst.isin([x for x in all_public_ips.keys() if x in best_net])] = str(best_net[0])
        return str(best_net[0]), df
    else:
        LOGGER.critical("Could not infer a target IP address from the data.")
        sys.exit(-1)


# ----------------------------------------------------------------------------------------------------------------------
