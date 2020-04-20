"""
Here lives the location configuration for DDoSDB

DDoSDB utilises several other programs that may only work on Linux or macOS.
"""

# Path to the file program
FILE = "file"
# Path to bittwiste
BITTWISTE = "bittwiste"
# Path to tshark
TSHARK = "tshark"
# Path to editcap
EDITCAP = "editcap"
# Location to output the fingerprints and attack vector to
OUTPUT_LOCATION = "output/"
# Amount of concurrent attack vector operations, increase at your own risk
POOL_SIZE = 4

DDOSDB_URL = "http://10.0.0.10/"

# Username for DDoSDB for uploading the attack vector and fingerprint
USERNAME = "ddosdb"
#USERNAME = "root"
# Password for DDoSDB for uploading the attack vector and fingerprint
PASSWORD = "071739440782b7c6581241607acca8b7"
#PASSWORD = "root"
