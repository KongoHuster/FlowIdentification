import os
import time

path = "./InsertPcap"
files = os.listdir(path)
files.sort()
count = 0

for file in files:
    if file.endswith(".pcap"):
       print(count)
       command = "tcpreplay -i ens33 -M 10 ./InsertPcap/" + str(file) 
       print(command)
       os.system(command)
       count = count + 1
       time.sleep(15)
       print("\n")
   
