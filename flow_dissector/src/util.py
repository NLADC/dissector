import sys
import pandas as pd
from configparser import ConfigParser, NoOptionError, NoSectionError
from pathlib import Path
from typing import List, Union, Dict, Tuple

from logger import LOGGER

__all__ = ["AMPLIFICATION_SERVICES", "TCP_FLAG_NAMES", "print_logo", "error", "get_outliers", "parse_config"]

AMPLIFICATION_SERVICES: Dict[int, str] = {  # UDP port -> service name
    17: "Quote of the Day",
    19: "Chargen",
    53: "DNS",
    69: "TFTP",
    111: "TPC",
    123: "NTP",
    137: "NetBios",
    161: "SNMP",
    177: "XDMCP",
    389: "LDAP",
    500: "ISAKMP",
    520: "RIPv1",
    623: "IPMI",
    1434: "MS SQL",
    1900: "SSDP",
    3283: "Apple Remote Desktop",
    3389: "Windows Remote Desktop",
    3702: "WS-Discovery",
    5093: "Sentinel",
    5351: "NAT-PMP",
    5353: "mDNS",
    5683: "CoAP",
    11211: "MEMCACHED",
    27015: "Steam",
    32414: "Plex Media",
    33848: "Jenkins",
    37810: "DHDiscover"
}

TCP_FLAG_NAMES: Dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RESET",
    "P": "PUSH",
    "A": "ACK",
    "U": "URGENT",
}


def print_logo() -> None:
    """
    Print the Dissector logo
    Returns:
        None
    """
    print('''
    ____  _                     __            
   / __ \(_)____________  _____/ /_____  _____
  / / / / / ___/ ___/ _ \/ ___/ __/ __ \/ ___/
 / /_/ / (__  |__  )  __/ /__/ /_/ /_/ / /    
/_____/_/____/____/\___/\___/\__/\____/_/     
''')


def error(message: str):
    LOGGER.error(message)
    sys.exit(-1)


def get_outliers(data: pd.DataFrame,
                 column: Union[str, List[str]],
                 fraction_for_outlier: float = 0.8,
                 use_zscore: bool = True,
                 return_fractions: bool = False) -> list:
    """
    Find the outlier(s) in a pandas Series
    :param data: data in which to find outlier(s)
    :param column: column or combination of columns in the dataframe for which to find outlier value(s)
    :param fraction_for_outlier: if a value comprises this fraction or more of the data, it is considered an outleir
    :param use_zscore: Also take into account the z-score to determine outliers (> 2 * std from the mean)
    :param return_fractions: Return the fractions of traffic occupied by each outlier.
    :return:
    """
    packets_per_value = data.groupby(column).nr_packets.sum().sort_values(ascending=False)
    fractions = packets_per_value / packets_per_value.sum()
    zscores = (fractions - fractions.mean()) / fractions.std()

    outliers = [(key, round(fraction, 3)) if return_fractions else key
                for key, fraction in fractions.items()
                if fraction > fraction_for_outlier or (zscores[key] > 2 and use_zscore)]

    if len(outliers) > 0:
        LOGGER.debug(f"Outlier(s) in column '{column}': {outliers}")
    else:
        LOGGER.debug(f"No outlier found in column '{column}'")
    return outliers


def parse_config(file: Path) -> Tuple[str, str, str]:
    """
    Parse the DDoSDB config file and return host, username, password
    :param file: Config file (ini format)
    :return: host (str), username (str), password (str)
    """
    config = ConfigParser()
    LOGGER.debug(f"Using ddosdb config file: '{str(file)}'")
    try:
        with open(file) as f:
            config.read_file(f)
    except FileNotFoundError:
        error("Uploading to DDoSDB failed. "
              f"DDoSDB config file '{file}' not found. Provide a config file like ddosdb.ini.example")

    try:
        return config.get('ddosdb', 'host'), config.get('ddosdb', 'user'), config.get('ddosdb', 'pass')
    except (NoSectionError, NoOptionError):
        error("Uploading to DDoSDB failed. "
              "The DDoSDB config file must include a section 'ddosdb' with keys 'host', 'user', and 'pass'.")
