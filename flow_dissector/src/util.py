import sys
import pandas as pd
from configparser import ConfigParser, NoOptionError, NoSectionError
from pathlib import Path
from typing import List, Union, Dict, Tuple

from logger import LOGGER

__all__ = ["PORT_PROTO_SERVICE", "print_logo", "error", "get_outliers", "parse_config"]

PORT_PROTO_SERVICE: Dict[Tuple[str, int], str] = {
    ("UDP", 53): "DNS",
    ("UDP", 123): "NTP",
    ("UDP", 32414): "PLEX",
    # ("", ): "",
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
                 use_zscore: bool = True) -> list:
    """
    Find the outlier(s) in a pandas Series
    :param data: data in which to find outlier(s)
    :param column: column or combination of columns in the dataframe for which to find outlier value(s)
    :param fraction_for_outlier: if a value comprises this fraction or more of the data, it is considered an outleir
    :param use_zscore: Also take into account the z-score to determine outliers (> 2 * std from the mean)
    :return:
    """
    packets_per_value = data.groupby(column).nr_packets.sum().sort_values(ascending=False)
    fractions = packets_per_value / packets_per_value.sum()

    if use_zscore:
        zscores = (fractions - fractions.mean()) / fractions.std()
        # More than 2 STDs above the mean or more than x% of data -> outlier
        outliers = [key for key in fractions.keys() if zscores[key] > 2 or fractions[key] > fraction_for_outlier]
    else:
        # More than x% of data -> outlier
        outliers = [key for key in fractions.keys() if fractions[key] > fraction_for_outlier]

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
