import pandas as pd
import os


def portnumber2name(port_number):
    port_path = "port_name.txt"
    if not os.path.isfile(port_path):
        port_path = "functions/" + port_path
    
    df_port_name = pd.read_csv(port_path, delimiter=",", names=['port_num', 'port_name'])
    try:
        return df_port_name[df_port_name['port_num'] == port_number]['port_name'].values[0]+" service port"
    except:
        return "port " + str(int(port_number))

