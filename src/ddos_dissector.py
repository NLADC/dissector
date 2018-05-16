
# coding: utf-8

# In[4]:


import os
import time
from threading import Thread

from functions.input2filetype import *
from functions.input2dataframe import *
from functions.dataframe2fingerprints import *
from functions.input2filteredanon import *

import warnings
warnings.filterwarnings('ignore')


# In[5]:


def ddos_dissector(input_file, debug):
#########################################################    
    print('\n1. Analysing the type of input file (e.g., pcap, pcapng, nfdump, netflow, and ipfix)...') 
    file_type = input2filetype(input_file)
#########################################################     
    print('\n2. Converting input file to dataframe...') 
    df = input2dataframe(input_file, file_type) 
#########################################################        
    print('\n3. Analysing the dataframe for finding attack patterns...')
    victim_ip, fingerprints = dataframe2fingerprints(df, file_type, debug)
######################################################### 
    print('\n4. Creating annonymized files containing only the attack vectors...\n')
    for fingerprint in fingerprints:
        input2fileredanon(input_file, file_type, victim_ip, fingerprint)
######################################################### 
    print("\n\nDONE!!!!!")
    #ADD A MANUAL STEP FOR OPERATORS REMOVE SUSPICIOUS ATTACK VECTORS (BETTER TRUE POSITIVE)


# In[9]:


# # FOR TESTING PURPOSES
# input_file="input4test/dns.pcap"
# ddos_dissector(input_file, debug=False)


# In[ ]:


if __name__ == '__main__':
    import argparse
    import os.path
    
    parser = argparse.ArgumentParser(description='')
    
    parser.add_argument('--input', metavar='input_file', required=True,
                        help='Path of a input file')
    
    parser.add_argument('--debug', metavar='debug', required=False, default=False,
                        help='enable debug')
    
    args = parser.parse_args()
    
    input_file=args.input
    debug=args.debug
    
    if os.path.isfile(input_file) == True:
        ddos_dissector(input_file, debug)
    else:
        print("We were unable to find the file. Please check the file path!!")

