
# coding: utf-8

# In[1]:


import random

ips =[]

def generating_ips(int):
    for x in range(0,int):
        ip = '{}.{}.{}.{}'.format(*__import__('random').sample(range(0, 255), 4))
        ips.append(ip) 
        
    return ips

