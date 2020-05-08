import os

command = "tcpdump -i ens33 -n -B 919400 -c 10000 -w Tcpdump.pcap"
os.system(command)

print("over")

