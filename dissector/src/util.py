import sys
import pandas as pd
import socket
import os
from enum import Enum
from typing import Dict, Union, List
from pathlib import Path
from configparser import ConfigParser, NoOptionError, NoSectionError

from logger import LOGGER

__all__ = ["IPPROTO_TABLE", "AMPLIFICATION_SERVICES", "TCP_FLAG_NAMES", "FileType", "determine_filetype", "print_logo",
           "error", "parse_config", "get_outliers"]

IPPROTO_TABLE: Dict[int, str] = {
    num: name[8:]
    for name, num in vars(socket).items()
    if name.startswith("IPPROTO")
}

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
    10074: "Mitel MiColab",  # CVE-2022-26143
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


class FileType(Enum):
    """
    PCAP or FLOW traffic capture file options
    """
    FLOW = "Flow"
    PCAP = "PCAP"

    def __str__(self):
        return self.value


def determine_filetype(filenames: List[Path]) -> FileType:
    """
    Determine whether the input files are Flows or PCAPs; if it's neither or a mix, quit.
    :param filenames:
    :return: PCAP or FLOW
    """
    filetype = None
    for filename in filenames:
        if not filename.exists() or not filename.is_file() or not os.access(filename, os.R_OK):
            error(f"{filename} does not exist or is not readable. If using docker, did you mount the location "
                  f"as a volume?")

        if filename.suffix.lower() == ".pcap" and filetype in [FileType.PCAP, None]:
            filetype = FileType.PCAP
        elif filename.suffix.lower() == ".nfdump" and filetype in [FileType.FLOW, None]:
            filetype = FileType.FLOW
        else:
            if filetype is None:
                error(f"File extesion '{filename.suffix}' not recognized. "
                      "Please use .pcap for PCAPS and .nfdump for Flows.")
            else:
                error("Please use only one type of capture file to create a fingerprint (.pcap or .nfdump)")
    LOGGER.debug(f"Input file type: {filetype}")
    return filetype if filetype is not None else error("No valid input files given.")


def print_logo() -> None:
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


def parse_config(file: Path, misp=False) -> Dict[str, str]:
    """
    Parse the DDoSDB/MISP config file and return host, username, password
    :param file: Config file (ini format)
    :param misp: Get the MISP credentials instead of DDoS-DB credentials.
    :return: host (str), username (str), password (str)
    """
    config = ConfigParser()
    LOGGER.debug(f"Using config file: '{str(file)}'")
    try:
        with open(file) as f:
            config.read_file(f)
    except FileNotFoundError:
        error("Uploading fingerprint failed. "
              f"Config file '{file}' not found. Provide a config file like ddosdb.ini.example with --config")

    platform = "misp" if misp else "ddosdb"
    try:
        return {
            "host": config.get(platform, 'host'),
            "username": config.get(platform, 'user'),
            "password": config.get(platform, 'pass')
        }

    except (NoSectionError, NoOptionError):
        error("Uploading fingerprint failed. "
              f"The config file must include a section '{platform}' with keys 'host', 'user', and 'pass'.")


def get_outliers(data: pd.DataFrame,
                 column: Union[str, List[str]],
                 fraction_for_outlier: float = 0.8,
                 use_zscore: bool = True,
                 return_fractions: bool = False,
                 return_others: bool = False) -> list:
    """
    Find the outlier(s) in a pandas DataFrame
    :param data: DataFrame in which to find outlier(s)
    :param column: column or combination of columns in the dataframe for which to find outlier value(s)
    :param fraction_for_outlier: if a value comprises this fraction or more of the data, it is considered an outleir
    :param use_zscore: Also take into account the z-score to determine outliers (> 2 * std from the mean)
    :param return_fractions: Return the fractions of traffic occupied by each outlier.
    :param return_others: in the outliers, return the fraction of "others" - i.e., the non-outlier values combined
    :return:
    """
    packets_per_value = data.groupby(column).nr_packets.sum().sort_values(ascending=False)
    fractions = packets_per_value / packets_per_value.sum()

    zscores = (fractions - fractions.mean()) / fractions.std()
    LOGGER.debug(f"top 5 '{column}':\n{fractions.head()}")

    outliers = [(key, round(fraction, 3)) if return_fractions or return_others else key
                for key, fraction in fractions.items()
                if fraction > fraction_for_outlier or (zscores[key] > 2 and use_zscore)]

    if len(outliers) > 0:
        LOGGER.debug(f"Outlier(s) in column '{column}': {outliers}\n")
        if return_others and (explained := sum([fraction for _, fraction in outliers])) < 0.99:
            outliers.append(("others", round(1 - explained, 3)))
    else:
        LOGGER.debug(f"No outlier found in column '{column}'")
    return outliers
