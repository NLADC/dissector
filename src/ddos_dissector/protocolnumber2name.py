import pandas as pd
import os


def protocolnumber2name(ip_proto_number):
    proto_path = "ip_proto_name.txt"
    if not os.path.isfile(proto_path):
        proto_path = "functions/" + proto_path
    
    df_ip_proto_name = pd.read_csv(proto_path, delimiter=",", names=['proto_num','proto_name'])
    try:
        return df_ip_proto_name[df_ip_proto_name['proto_num'] == ip_proto_number]['proto_name'].values[0]
    except:
        return str(ip_proto_number)

