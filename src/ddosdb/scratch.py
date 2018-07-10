import math
from pprint import pprint

from ddosdb import file_type_parser

if __name__ == "__main__":
    a = file_type_parser.convert_pcap_to_dataframe(
        "C:\\Users\\Koen\\OneDrive - Universiteit Twente\\DDoSDB\\ddosdb\\src\\input4test\\1.pcap")