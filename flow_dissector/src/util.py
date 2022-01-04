import sys
import pandas as pd
from typing import List, Union

from logger import LOGGER

__all__ = ['error', 'get_outliers']


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
