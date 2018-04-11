
# coding: utf-8

# In[2]:


import subprocess
import random
import os
import datetime
import time


# In[ ]:


def tcpdump_filter_anon(input_file, pattern, dst_ip):


    # Filtering based on host/proto and ports
    if len(pattern['src_ports']) > 1:
        filter_out = "dst host " + dst_ip + " and proto " + str(pattern['ip_protocol']) + " and dst port " + str(pattern["dst_ports"].keys()[0])
    elif len(pattern['dst_ports']) > 1:
        filter_out = "dst host " + dst_ip + " and proto " + str(pattern['ip_protocol']) + " and src port " + str(pattern["src_ports"].keys()[0])
    
    #convert epoch time to datetime
    timestamp = time.strftime('%Y%m%d%H%M%S', time.localtime(pattern["start_timestamp"]))
    
    #proper filename based on start timestamp and selected port
    filename = timestamp + "_" + str(pattern["selected_port"]) + ".pcap"
    
    p = subprocess.Popen(["tcpdump -r " + input_file + " -w output/temp " + filter_out], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    #running bittwiste for anonymizing destination ip
    p = subprocess.Popen(["bittwiste -I " + "output/temp " + " -O output/" + filename + " -T ip -d " + dst_ip + ",1.1.1.1"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    #remove temporary file after anonymization took place
    p = subprocess.Popen(["rm -rf output/temp"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    
    return "Attack vector created and anonymized."

