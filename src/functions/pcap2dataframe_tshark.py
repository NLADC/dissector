
# coding: utf-8

# In[21]:


import subprocess
import pandas as pd
import os.path


# In[33]:


def pcap2dataframe_tshark(filename):
    """
    Read PCAP and produce Pandas dataframe.
    """
    
    tshark_fields = "-e frame.time_epoch "+                "-e _ws.col.Source " +                "-e _ws.col.Destination "+                "-e _ws.col.Protocol " +                "-e frame.len " +                "-e ip.ttl " +                "-e ip.flags.mf " +                "-e ip.frag_offset " +                "-e icmp.type " +                "-e tcp.srcport " +                "-e tcp.dstport " +                "-e udp.srcport " +                "-e udp.dstport " +                "-e dns.qry.name " +                "-e dns.qry.type " +                "-e http.request " +                "-e http.response " +                "-e http.user_agent " +                "-e tcp.flags.str " +                "-e quic.payload " +                "-e ssl.app_data "
    
    with open("intermediate_file.csv","wb") as output_file:
        p = subprocess.Popen(["tshark -n -r " + filename + " -E separator=\;  -E header=y -T fields " +  tshark_fields], shell=True, stdout=output_file)
        p.communicate()
        p.wait()
    
    if os.path.exists("intermediate_file.csv") == False:
        print ('ATTENTION: THE INTERMEDIATED FILE WAS NOT CREATED!')

    ###
    df = pd.read_csv("intermediate_file.csv", sep=';',  low_memory=False, index_col=False)
    ###
    if ('tcp.srcport' in df.columns) & ('udp.srcport' in df.columns) & ('tcp.dstport' in df.columns) & ('udp.dstport' in df.columns):
        ###Combining source and destination ports from tcp and udp
        df['srcport'] = df['tcp.srcport'].fillna(df['udp.srcport'])
        df['dstport'] = df['tcp.dstport'].fillna(df['udp.dstport'])

        df['srcport'] = df['srcport'].apply(lambda x: int(x) if str(x).replace('.','',1).isdigit() else None)
        df['dstport'] = df['dstport'].apply(lambda x: int(x) if str(x).replace('.','',1).isdigit() else None)

    ###Removing columns: 'tcp.srcport', 'udp.srcport','tcp.dstport', 'udp.dstport'
    df.drop(['tcp.srcport', 'udp.srcport','tcp.dstport', 'udp.dstport' ], axis=1, inplace=True)

    ###Dropping all empty columns (for making the analysis more efficient! less memory.)
    df.dropna(axis=1, how='all', inplace=True)

    if ('icmp.type' in df.columns):
        df['icmp.type']=df['icmp.type'].astype(str) 

    if ('ip.frag_offset' in df.columns):
        df['ip.frag_offset']=df['ip.frag_offset'].astype(str) 

    if ('ip.flags.mf' in df.columns):
        df['ip.flags.mf']=df['ip.flags.mf'].astype(str) 

    if ('ip.flags.mf' in df.columns) & ('ip.frag_offset' in df.columns):
        ###Analysing fragmented packets
        df['fragmentation'] = (df['ip.flags.mf']== '1') | (df['ip.frag_offset']!='0')
        df.drop(['ip.flags.mf','ip.frag_offset' ], axis=1, inplace=True)

    df['ip.ttl'] = df['ip.ttl'].apply(lambda x: int(x) if str(x).isdigit() else None)
    
    p = subprocess.Popen(["rm intermediate_file.csv"], shell=True, stdout=subprocess.PIPE)
    p.communicate()
    p.wait()
    
    return df

