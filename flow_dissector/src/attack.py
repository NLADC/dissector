from typing import List
import numpy as np
import pandas as pd
from netaddr import IPAddress, IPNetwork

from fingerprint import AttackVector
from logger import LOGGER
from util import error


class Attack:
    def __init__(self, data: pd.DataFrame):
        self.data = data
        self.ensure_datatypes()
        self.attack_vectors: List[AttackVector]

    def ensure_datatypes(self):
        """
        Cast each DataFrame column to the correct type
        :return: None
        """
        def try_cast(colomn_name: str, to_type: type, essential: bool = False) -> None:
            try:
                self.data[colomn_name] = self.data[colomn_name].astype(to_type)
            except KeyError as c:
                LOGGER.critical(f"{str(c).replace('_', ' ')} not in FLOW data")
                if essential:
                    error("Cannot continue with incomplete data")

        try:
            self.data['time_start'] = pd.to_datetime(self.data['time_start'])
            self.data['time_end'] = pd.to_datetime(self.data['time_start'])
        except KeyError as col:
            error(f"{str(col).replace('_', ' ')} not in FLOW data")
        except ValueError:
            error(f"time_start or time_end column cannot be interpreted as datetime")
        try:
            self.data['source_address'] = self.data['source_address'].apply(IPAddress)
            self.data['destination_address'] = self.data['destination_address'].apply(IPAddress)
        except KeyError as col:
            error(f"{str(col).replace('_', ' ')} not in FLOW data")

        try_cast('protocol', to_type=str, essential=True)
        try_cast('source_port', to_type=np.ushort, essential=True)
        try_cast('destination_port', to_type=np.ushort, essential=True)
        try_cast('nr_packets', to_type=int)
        try_cast('nr_bytes', to_type=int)
        try_cast('tcp_flags', to_type=str)

    def filter_data_on_target(self, target_network: IPNetwork):
        """
        Only keep traffic directed at the target in Attack.data
        :param target_network: target network of this attack
        :return: None
        """
        target_addresses = [x for x in self.data.destination_address if x in target_network]
        self.data = self.data[self.data.destination_address.isin(target_addresses)]
