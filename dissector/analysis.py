import pandas as pd
from typing import List, Any, Optional

from config import LOGGER, Filetype


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


def infer_target(df: pd.DataFrame) -> List[str]:
    """
    Infer the target IP address(es) of the attack described by the given dataframe
    Args:
        df: attack data

    Returns:
        List of IPs (str)
    """
    if (outlier := find_outlier(df, 'ip_dst')) is not None:
        return [outlier]
    # TODO same subnet
