
# coding: utf-8

# In[ ]:


import subprocess
import random
import os
import datetime
import time
import hashlib


# In[ ]:


def tcpdump_filter_anon(input_file, fingerprint, dst_ip, file_type):
    # Filtering based on host/proto and ports
    
    print(fingerprint)
    
    print('\n')
    print(len(fingerprint['src_ports']))
    print(len(fingerprint['dst_ports']))
    
    if len(fingerprint['src_ports']) == 1:
        filter_out = "dst host " + dst_ip + " and proto " + str(fingerprint['protocol']) + " and src port " + str(fingerprint["src_ports"][0])
        
    elif len(fingerprint['dst_ports']) == 1:
        filter_out = "dst host " + dst_ip + " and proto " + str(fingerprint['protocol']) + " and dst port " + str(fingerprint["dst_ports"][0])
    else:
        print ('problem')
        
    filename=str(hashlib.md5(str(fingerprint['start_time']).encode()).hexdigest())+str(file_type)
    
    print(filter_out)
    
    print(filename)
    p = subprocess.Popen(["tcpdump -r " + input_file + " -w output/"+filename+" "+ filter_out], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
#     #running bittwiste for anonymizing destination ip
#     p = subprocess.Popen(["bittwiste -I " + "output/temp " + " -O output/" + filename + " -T ip -d " + dst_ip + ",1.1.1.1"], shell=True, stdout=subprocess.PIPE)
#     p.communicate()
#     p.wait()
    
#     #remove temporary file after anonymization took place
#     p = subprocess.Popen(["rm -rf output/temp"], shell=True, stdout=subprocess.PIPE)
#     p.communicate()
#     p.wait()
    

