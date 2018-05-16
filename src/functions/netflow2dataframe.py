
# coding: utf-8

# In[1]:


import pandas
import subprocess
import numpy
import time

def netflow2dataframe(file_input):

    temp_file_path = "/tmp/nflow.csv"

    #Convert nflow to csv
    p = subprocess.Popen(["nfdump -r " + file_input + " -o extended -o csv > " + temp_file_path], shell=True, stdout=subprocess.PIPE)
    file_info, error = p.communicate()
    p.wait()
    
    columns = [ 'start_time', #ts,
                'end_time',# te,
                'time duration',#td,
                'src_ip',#sa,
                'dst_ip',#da,
                'src_port',#sp,
                'dst_port',#dp,
                'ip_proto',#pr,
                'tcp_flag',#flg,
                'forwarding',#fwd,
                'src_tos',#stos,
                'i_packets',#ipkt,
                'i_bytes',#ibyt,
                'o_packets',#opkt,
                'o_bytes',#obyt,
                'i_interface_num',#in,
                'o_interface_num',#out,
                'src_as',#sas,
                'dst_as',#das,
                'src_mask',#smk,
                'dst_mask',#dmk,
                'dst_tos',#dtos,
                'direction',#dir,
                'next_hop_ip',#nh,
                'bgt_next_hop_ip',#enhb,
                'src_vlan_label',#svln,
                'dst_vlan_label',#dvln,
                'i_src_mac',#ismc,
                'o_dst_mac',#odmc,
                'i_dst_mac',#idmc,
                'o_src_mac',#osmc,
                'mpls1',
                'mpls2',
                'mpls3',
                'mpls4',
                'mpls5',
                'mpls6',
                'mpls7',
                'mpls8',
                'mpls9',
                'mpls10',
                'cl',
                'sl',
                'al',
                'ra',
                'eng',
                'exid',
                'tr']
    try:
        df = pandas.read_csv(temp_file_path)
    except Exception:
        print(Exception)
        print("Pandas can't read the csv flow file. Exiting.")
        return

    summary = df.iloc[[len(df)-1]]
    total_flows = summary.iloc[0]['ts']
    total_bytes = summary.iloc[0]['te'] #raw_size
    total_packets = summary.iloc[0]['td']
    summary = [total_flows, total_bytes, total_packets]
    
    df.dropna(inplace=True,how='any')
    
    df['dp'] = df['dp'].astype('int32')
    df['ibyt'] = df['ibyt'].astype('int32')
    df['sp'] = df['sp'].astype('int32')
    
    df.columns = columns

# #No need to remove. Will be used later.
#     try:
#         subprocess.call("rm " + temp_file_path, shell=True) #Unsafe
#     except:
#         pass
    
    
    
    return df, summary

