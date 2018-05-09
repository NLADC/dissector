
# coding: utf-8

# In[15]:


import subprocess
import random
import os
import os.path
import datetime
import time
import hashlib
import platform
import numpy as np


# In[19]:


def tshark_filter_anon(input_file, fingerprint, dst_ip, file_type):

    
    if len(fingerprint['src_ports']) == 1 and fingerprint['src_ports'][0] != np.nan:
        filter_out = "\"ip.dst == " + dst_ip + " and " + str(fingerprint['protocol']).lower() + " and (tcp.srcport == " + str(int(fingerprint["src_ports"][0]))+" or udp.srcport == "+ str(int(fingerprint["src_ports"][0]))+")\""
        
    elif len(fingerprint['dst_ports']) == 1 and fingerprint['dst_ports'][0] != np.nan:
        filter_out = "\"ip.dst == " + dst_ip + " and " + str(fingerprint['protocol']).lower() + " and (tcp.dstport == " + str(int(fingerprint["dst_ports"][0]))+" or udp.dstport == "+ str(int(fingerprint["dst_ports"][0]))+")\""
    
    else:
        filter_out = "\"ip.dst == " + dst_ip + " and " + str(fingerprint['protocol']).lower()+"\""
    
    filename=str(hashlib.md5(str(fingerprint['start_timestamp']).encode()).hexdigest())+"."+str(file_type)
    
    p = subprocess.Popen(["tshark -r " + input_file + " -w output/temp.pcapng -Y "+ filter_out], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

    p = subprocess.Popen(["editcap -F libpcap -T ether output/temp.pcapng output/temp.pcap"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait() 
    
    if os.path.exists("output/temp.pcap"):
        if platform.system() == 'Darwin':
            command = "/usr/local/Cellar/bittwist/2.0/bin/bittwiste -I output/temp.pcap -O output/" + filename + " -T ip -d " + dst_ip + ",127.0.0.1"
            p = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE)
            p.communicate()
            p.wait()
        
        else:
            p = subprocess.Popen(["bittwiste -I " + "output/temp.pcap -O output/" + filename + " -T ip -d " + dst_ip + ",127.0.0.1"], shell=True, stdout=subprocess.PIPE)
            p.communicate()
            p.wait()
                          
    if os.path.exists("output/"+filename):
        p = subprocess.Popen(["rm -rf output/temp.pcap output/temp.pcapng"], shell=True, stdout=subprocess.PIPE)
        p.communicate()
        p.wait()
#     #remove temporary file after anonymization took place
#     
    

