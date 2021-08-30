from enum import Enum
import sys
import cursor
from logging import Logger
from argparse import Namespace
from typing import List, Optional
import signal

from logger import get_logger
from user_interaction import get_argument_parser

__all__ = ['FILE_NAMES', 'VERBOSE', 'QUIET', 'DEBUG', 'NOVERIFY', 'DB_CONF_FILE', 'CHECK_VERSION', 'CHECK_DB_STATUS',
           'SHOW_SUMMARY', 'LOGGER',  'Filetype', 'ctrl_c_handler']

# INFO: Code in this file's body is only executed when the file is imported for the first time, in Dissector.py

# Parse command line arguments
args: Namespace = get_argument_parser().parse_args()

# Global variables
FILE_NAMES: Optional[List[str]] = args.filename
VERBOSE: bool = args.verbose
QUIET: bool = args.quiet
DEBUG: bool = args.debug
NOVERIFY: bool = args.noverify
DB_CONF_FILE: str = args.dbconfig
CHECK_VERSION: bool = args.version
CHECK_DB_STATUS: bool = args.dbstatus
SHOW_SUMMARY: bool = args.summary
DB_HOST: str = args.host
DB_USER: str = args.user
DB_pass: str = args.passwd
LOGGER: Logger = get_logger(DEBUG, VERBOSE)


class Filetype(Enum):
    """
    Enumeration of traffic file types (PCAP, FLOW)
    """
    PCAP = 1
    FLOW = 2


def ctrl_c_handler(signum: int, stack_frame) -> None:
    """
    Handler for KeyboardInterruptException for async events
    """
    sys.stdout.flush()
    cursor.show()
    LOGGER.debug(f"Signal {signum} received, stack frame: {stack_frame}. Exiting.")
    sys.exit(0)
