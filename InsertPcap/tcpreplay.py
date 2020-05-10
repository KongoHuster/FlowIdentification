import os
import time

path = "./InsertPcap2/"
files = os.listdir(path)
files.sort()
count = 0

for file in files:
    if file.endswith(".pcap"):
       print(file)
       print(count)
       command = "tcpreplay -i ens33 -M 10 " + path + str(file) 
       print(command)
       os.system(command)
       count = count + 1
       time.sleep(10)
       print("\n")   
