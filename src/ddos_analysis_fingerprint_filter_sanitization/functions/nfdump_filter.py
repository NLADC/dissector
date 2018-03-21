
# coding: utf-8

# In[7]:


import subprocess
def nfdump_filter(input_file, patterns):
    """
    Creates an nfdump filter based on a set of characteristics
    :param src_ips:
    :return:
    """
    # Array containing all the individual filters
    output_filter = []
    
    for pattern in patterns:
    
        # Filter by protocol
        if len(pattern['ip_protocol']) > 0:
            protocol_filter = ["proto " + pattern['ip_protocol']]
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
        
    f = open("/tmp/filter.out", "w")
    f.write(filter_out)
    f.close()
    
    p = subprocess.Popen(["nfdump -r " + input_file + " -f /tmp/filter.out -w output/vector.nfdump"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    print ' Done!'
    
    return 


# The function above seems to be hitting the limitation of being single threaded, and writing the output after every filter. The execution time with 100 000 IP addresses and 65335 port numbers takes approximately 16 minutes and never exceeds 18% CPU usage, which corresponds with two cores on an eight-core system.
