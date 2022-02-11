import shutil
import os
import subprocess
import pandas as pd
from typing import Dict
from pathlib import Path
from io import StringIO

from logger import LOGGER
from util import error

__all__ = ['read_flow']

COLUMN_NAMES: Dict[str, str] = {
    'ts': "time_start",
    'te': "time_end",
    'pr': "protocol",
    'sa': "source_address",
    'da': "destination_address",
    'sp': "source_port",
    'dp': "destination_port",
    'ipkt': "nr_packets",
    'ibyt': "nr_bytes",
    'flg': "tcp_flags"
}


def read_flow(filename: Path) -> pd.DataFrame:
    """
    Load the FLOW capture into a dataframe
    :param filename: location of the FLOW file
    :return: DataFrame of the contents
    """
    # Check if nfdump software is available
    nfdump = shutil.which("nfdump")
    if nfdump is None:
        error("nfdump software not found; it should be on the $PATH. Install from https://github.com/phaag/nfdump")

    if not filename.exists() or not filename.is_file() or not os.access(filename, os.R_OK):
        error(f"{filename} does not exist or is not readable. If using docker, did you mount the location "
              f"as a volume? Did you use the correct path to the file in docker?")

    command = [nfdump, "-r", str(filename), "-o", "extended", "-o", "csv"]
    LOGGER.info(f'Reading "{filename}"...')
    process = subprocess.run(command, capture_output=True)
    if process.returncode != 0:
        LOGGER.error("nfdump command failed!\n")
        error(f"nfdump command stderr:\n{process.stderr.decode('utf-8')}")
    LOGGER.debug("nfdump finished reading FLOW dump.")

    # Process nfdump output
    rows = process.stdout.decode("utf-8").split('\n')
    flows = '\n'.join(rows[:-4])
    LOGGER.info("Loading data into a dataframe.")
    data: pd.DataFrame = pd.read_csv(StringIO(flows), encoding="utf8")

    # Keep only relevant columns & rename
    data = data[data.columns.intersection(COLUMN_NAMES.keys())]
    data.rename(columns=COLUMN_NAMES, inplace=True)
    LOGGER.debug("Done loading data into dataframe.")
    return data
