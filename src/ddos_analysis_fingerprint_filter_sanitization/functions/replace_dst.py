
# coding: utf-8

# In[1]:


import pandas
import subprocess

def replace_ipindf(df,dst_ip):
    df.replace(
        to_replace=dst_ip,
        value='8.8.8.8', #any value you wish to replace it to
        inplace=True,
        limit=None,
        regex=False, 
        method='pad',
        axis=None)
    
    return



def replace_ipinpcap(input_pcap,ip):
    p = subprocess.Popen(["bittwiste -I " + input_pcap + " -O output/replaced_ip.pcap -T ip -s " + ip + ",1.1.1.1 -d " + ip + ",1.1.1.1"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    print "IP replaced"
    return



