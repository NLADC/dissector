
# coding: utf-8

# In[1]:


import subprocess
import os
import time


# In[2]:


def nfdump_filter_anon(input_file, pattern, dst_ip):
    
    # Filtering based on host/proto and ports
    if len(pattern['src_ports']) > 1:
        filter_out = "dst ip " + dst_ip + " and proto " + str(pattern['ip_protocol']) + " and dst port " + str(pattern["dst_ports"].keys()[0])
    else:
        filter_out = "dst ip " + dst_ip + " and proto " + str(pattern['ip_protocol']) + " and src port " + str(pattern["src_ports"].keys()[0])
        
    #proper filename based on start timestamp and selected port
    timestamp = pattern["start_timestamp"].split()
    filename =  timestamp[0].replace("-", "") + timestamp[1].replace(":", "") + "_" + str(pattern["selected_port"]) + ".nfdump"
    
    p = subprocess.Popen(["functions/nfdump_modified/bin/nfdump -r " + input_file + " -w output/nfdumptemp " + "'" + filter_out + "'"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    p = subprocess.Popen(["functions/nfdump_modified/bin/nfanon -r output/nfdumptemp -c '127.0.0.1' -w output/" + filename], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    p = subprocess.Popen(["rm output/nfdumptemp"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()

