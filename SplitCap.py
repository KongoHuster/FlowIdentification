# encoding:utf-8
import os
import time
def execCommand(command):
        print(command)
        os.system(command)
        print('\n')

typeNameArray = ["Benign","Malware"]

rootPath = "/root/TrafficSet/"

for typeName in typeNameArray: #流量种类
    stringConmmand = "mono SplitCap.exe -r " + rootPath  + "DataSet/" + typeName

    path = "/root/TrafficSet/DataSet/" + typeName
    files = os.listdir(path)

    for file in files:  #流量中的数据包
        if file.endswith("BaiDuWangPan.pcap"):
            fileName = file.split('.')[0]
            command = stringConmmand  + "/" + file + " -o " + rootPath + "PreCapture/" + typeName + "/" + fileName + "/" + "FlowAllLayers -s flow -p 1018"
            #execCommand(command)
            print(command)
            p = os.popen(command)
            print(p.read())
            print('\n')

            command = stringConmmand  + "/" + file + " -o " + rootPath + "PreCapture/" + typeName + "/" + fileName + "/" + "FlowL7" + " -y L7 -s flow -p 1018"
            #execCommand(command)
            print(command)
            p = os.popen(command)
            print(p.read())
            print('\n')


            command = stringConmmand  + "/" + file + " -o " + rootPath + "PreCapture/" + typeName + "/" + fileName + "/" + "SessionAllLayers"  + " -s session -p 1018"
            #execCommand(command)
            print(command)
            p = os.popen(command)
            print(p.read())
            print('\n')

            command = stringConmmand  + "/" + file + " -o " + rootPath + "PreCapture/" + typeName + "/" + fileName + "/" + "SessionL7" + " -s session" + " -y L7 -p 1018"
            #execCommand(command)
            print(command)
            p = os.popen(command)
            print(p.read())
            print('\n')

