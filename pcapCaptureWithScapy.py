from scapy.all import *
import pcap
from PIL import Image
import binascii
import numpy
from keras.models import load_model
import os
import dpkt
import time
from timeit import default_timer as timer
import collections
import threading

def getMatrixfrom_pcap(filename,width):
    with open(filename, 'rb') as f:
        content = f.read()
    hexst = binascii.hexlify(content)
    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
    if len(fh)<784:
        x = numpy.zeros(784)
        x[:len(fh)]=fh
        fh = x
    if len(fh)>784:
        fh = fh[:784]
    rn = int(len(fh)/width)
    fh = numpy.reshape(fh[:(rn*width)],(-1,width))
    fh = numpy.uint8(fh)
    return fh

def printPcapInformation(path):
    packets = rdpcap(path)
    print("timestamp:" + str(packets[0][IP].time))
    print("src_ip:" + str(packets[0][IP].src))
    print("dest_ip:" + str(packets[0][IP].dst))
    print("src_port:" + str(packets[0][IP].sport))
    print("dest_port:" + str(packets[0][IP].dport))


def process(command,path):
    t1 = timer()
    p = os.popen(command)
    time.sleep(0.4)
    files = os.listdir(path)
    # t2 = timer()
    # print("数据切割时间" + str(t2-t1))

    # files = os.listdir("./SshAttack/FlowAllLayers/")
    malware_list = []
    begnin_list = []
    malware_path = ""
    # t1 = timer()
    for file in files:   
        # print(path+file)
        fh = getMatrixfrom_pcap(str(path+file), PNG_SIZE)
        #fh = getMatrixfrom_pcap(str("./SshAttack/FlowAllLayers/" + file), PNG_SIZE)
        im = Image.fromarray(fh)
        image = numpy.reshape(fh,(-1,28,28,1))
        result = model1.predict_classes(image)
        # print(result)
        if result[0] == 1:
            # print(result)
            result = model2.predict_classes(image)
            # print(dict_10class_malware[result[0]])
            malware_list.append(result[0])
            malware_path = path+file
            # print("\n")
        else:
            result = model3.predict_classes(image)
            begnin_list.append(result)
            # print(dict_10class_benign[result[0]])


    if len(malware_list):
        # print(malware_list)
        temp = collections.Counter(malware_list)
        position = temp.most_common(1)[0][0]
        number = temp.most_common(1)[0][1]
        # print("64个数据包中" + str(dict_10class_malware[position]) + "的个数:" + str(number))

        if position == 9:
            if number > 1:
                print("警告：存在恶意流量")
                # printPcapInformation(malware_path)
                print("64个数据包中" + str(dict_10class_malware[position]) + "的个数:" + str(number))
            else:
                print("无恶意流量")
        elif position == 5:
            if number > 20:
                print("警告：存在恶意流量")
                printPcapInformation(malware_path)
                print("64个数据包中" + str(dict_10class_malware[position]) + "的个数:" + str(number))
            else:
                print("无恶意流量")
        else:
            if number > 20:
                print("警告：存在恶意流量")
                printPcapInformation(malware_path)
                print("64个数据包中" + str(dict_10class_malware[position]) + "的个数:" + str(number))
            else:
                print("无恶意流量")

    else:
        print("无恶意流量")

    t2 = timer()
    print("模型预测时间" + str(t2-t1))
    print("\n")

if __name__ == "__main__":
    t1 = timer()
    model1 = load_model('./LeNet-5Of2Class.h5')
    model2 = load_model('./LeNet-5Of10MalwareClass.h5') #10分类恶意
    model3 = load_model('./LeNet-5Of10BenignClass.h5') #10分类正常
    t2 = timer()
    print("模型加载时间" + str(t2-t1))
    dict_10class_malware = {0:'Cridex',1:'Botnet',2:'Htbot',3:'Miuref',4:'SshAttack',5:'Dedrop',6:'Shifu',7:'Tinba',8:'Scanner',9:'Nmap'}
    dict_10class_benign = {0:'BaiDuWangPan',1:'Bilibili',2:'BitTorrent',3:'FTP',4:'Gmail',5:'JianShu',6:'QQ',7:'Skype',8:'WeiBo',9:'Facetime'}

    PNG_SIZE = 28

    p = os.popen("rm -rf ./PcapSplit/*")
    p = os.popen("rm ./Pcap/*")

    count = 0

    # filter="src host 192.168.171.143 or dst host 192.168.171.143",
    print("模型加载完成")
    while True:
        filename = "./Pcap/demo" + str(count) + ".pcap"
        dpkt  = sniff(iface = "en2", count = 10000)
        #dpkt  = sniff(iface = "en2", count = 64)
        wrpcap(filename, dpkt)
        
        path = "./PcapSplit/demo" + str(count)+"/"
        if not os.path.exists(path):
            os.makedirs(path)

        command = 'mono SplitCap.exe -s session -r '+ filename + ' -o ' + "./PcapSplit/demo" + str(count)  + ' -p 1018'
        print(command)
        try:
            thread1 = threading.Thread(target=process,args=(command,path))
            thread1.setDaemon(True)
            thread1.start()
            thread1.join()

        except AttributeError: 
            print("AttributeError error\n")

        # except IndexError:
        #     print("IndexError error\n")

        count = count + 1


