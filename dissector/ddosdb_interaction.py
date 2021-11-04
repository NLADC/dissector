import os
import sys
import configparser
import requests
import urllib3
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

    LOGGER.info("Checking DDoSDB instance availability")
    for section in CONFIG.sections():
        LOGGER.info(f"[{section}]:")
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
            # TODO: how to check access?
            resp = requests.get(host + '/my-permissions', headers=headers, verify=not NOVERIFY)
            try:
                resp.raise_for_status()
                LOGGER.info("Available!")
            except requests.HTTPError:
                LOGGER.info(f'{host} is not available: {resp.status_code}, "{resp.text}"')


def upload(fingerprint_filename: os.PathLike, user: str, passw: str, host: str, key: str) -> int:
    """
    Upload a fingerprint to DDoSDB
    :param fingerprint_filename: path to fingerprint generated file
    :param user: DDoSDB username
    :param passw: DDoSDB password
    :param host: ddosdb instance url
    :param key: fingerprint identifier
    :return: status_code describing HTTP code received
    """

    if not os.path.isfile(fingerprint_filename):
        LOGGER.critical("Could not read the fingerprint json file {}".format(fingerprint_filename))

    files = {
        "json": open(fingerprint_filename, "rb"),
    }

    # build headers for repo fingerprint submission
    headers = {
        "X-Username": user,
        "X-Password": passw,
        "X-Filename": key
    }

    try:
        urllib3.disable_warnings()
        r = requests.post(host + "upload-file", files=files, headers=headers, verify=not NOVERIFY)
    except requests.exceptions.SSLError as e:
        LOGGER.critical("SSL Certificate verification of the server {} failed".format(host))
        LOGGER.info("If you trust {} re-run with --noverify / -n flag to disable certificate verification".format(host))
        LOGGER.debug("Cannot connect to the server to upload fingerprint: {}".format(e))
        return 500

    except requests.exceptions.RequestException as e:
        LOGGER.critical("Cannot connect to the server to upload fingerprint")
        LOGGER.debug("Cannot connect to the server to upload fingerprint: {}".format(e))
        LOGGER.info(e)
        return 500

    if r.status_code == 403:
        LOGGER.info("Invalid credentials or no permission to upload fingerprints:")
    elif r.status_code == 201:
        LOGGER.info("Upload success: \n\tHTTP CODE [{}] \n\tFingerprint ID [{}]".format(r.status_code, key))
        LOGGER.info("\tURL: {}query?q={}".format(host, key))
    else:
        LOGGER.info("Internal Server Error. Check repository Django logs.")
        LOGGER.info("Error Code: {}".format(r.status_code))
    return r.status_code
