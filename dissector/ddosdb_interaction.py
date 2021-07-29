import os
import sys
import configparser
import requests
from typing import Optional

from config import LOGGER, DB_CONF_FILE, NOVERIFY

__all__ = ['check_ddosdb_availability']


def get_ddosdb_conf() -> Optional[configparser.ConfigParser]:
    """
    Get the ddosdb config file parser
    Returns:
        ConfigParser
    """
    if os.path.isfile(DB_CONF_FILE) and os.access(DB_CONF_FILE, os.R_OK):
        msg = f"Using configuration file [{DB_CONF_FILE}]"
        sys.stdout.write('\r' + '[' + '\u2713' + '] ' + msg + '\n')
        config = configparser.ConfigParser()
        config.read(DB_CONF_FILE)
        return config
    else:
        LOGGER.info(f"Configuration file [{DB_CONF_FILE}] not found.")
        return None


CONFIG: Optional[configparser.ConfigParser] = get_ddosdb_conf()


def check_ddosdb_availability() -> None:
    """
    Check if the DDoSDB instances given in the config file are available and if the credentials are correct
    Returns:
        None
    """
    if CONFIG is None:
        LOGGER.critical(f"Could not load config file '{DB_CONF_FILE}'. Is the path correct?")

    LOGGER.info("Checking DDoSDB instances")
    for section in CONFIG.sections():
        print(f"[{section}]:")
        try:
            host = CONFIG[section]['host']
            user = CONFIG[section]['user']
            passwd = CONFIG[section]['passwd']
        except KeyError:
            LOGGER.warning(f"Configuration for [{section}] is invalid; should include 'host', 'user' and 'passwd'")
            continue
        else:
            headers = {
                "X-Username": user,
                "X-Password": passwd,
            }
            resp = requests.get(host, headers=headers, verify=not NOVERIFY)  # TODO: how to check access?
            try:
                resp.raise_for_status()
                print("Available!")
            except requests.HTTPError:
                print(f"{host} is not available.")
