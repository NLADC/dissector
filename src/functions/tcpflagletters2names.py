
# coding: utf-8

# In[1]:


def tcpflagletters2names(tcp_flags_str):
    tcp_flags=""
    try:
        tcp_flags += ("FIN" if (tcp_flags_str.find('F') != -1) else next)
    except:
        next
    try:
        tcp_flags += ("SYN" if (tcp_flags_str.find('S')!= -1) else next)
    except:
        next

    try:
        tcp_flags += ("RST" if tcp_flags_str.find('R') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("PUSH" if tcp_flags_str.find('P') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("ACK" if tcp_flags_str.find('A') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("URG" if tcp_flags_str.find('U') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("ECE" if tcp_flags_str.find('E') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("CWR" if tcp_flags_str.find('C') != -1 else next)
    except:
        next


    return tcp_flags

