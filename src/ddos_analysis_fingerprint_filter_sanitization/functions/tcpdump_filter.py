
# coding: utf-8

# In[ ]:


import subprocess
import random
import os


# In[1]:


def tcpdump_filter(input_file, pattern):
    """
    Creates an nfdump filter based on a set of characteristics
    :param src_ips:
    :return:
    """
    # Array containing all the individual filters
    output_filter = []
    
    
    # Filter by protocol
    if (pattern['ip_protocol']):
        protocol_filter = ["proto " + str(pattern['ip_protocol'])]
        output_filter.append(" or ".join(protocol_filter))

    # Filter by source IP
    if len(pattern['src_ips']) > 0:
        src_ip_filter = ["src ip " + ip for ip in pattern['src_ips']]
        output_filter.append(" or ".join(src_ip_filter))

    # Filter by port number
    if len(pattern['src_ports']) > 0:
        src_port_filter = ["src port " + str(port) for port in pattern['src_ports']]
        output_filter.append(" or ".join(src_port_filter))
        
    filter_out = "(" + ") and (".join(output_filter) + ")"
     
    while(1):
        nonce = str(random.randrange(0, 1000, 1))
        output_vector = "attack_vector_" + nonce
        if os.path.isfile(output_vector) == False:
            break
    
    filter_path = "/tmp/filter" + nonce
    f = open(filter_path, "w")
    f.write(filter_out)
    f.close()
    
    p = subprocess.Popen(["cat " + filter_path + " | tcpdump -r " + input_file + " -w output/" + output_vector + ".pcap"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    print ' Done!'
    
    return nonce

