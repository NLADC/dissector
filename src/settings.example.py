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

# Username for DDoSDB for uploading the attack vector and fingerprint
USERNAME = ""
# Password for DDoSDB for uploading the attack vector and fingerprint
PASSWORD = ""
