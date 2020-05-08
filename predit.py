#-*-coding:utf-8-*-
from scapy.all import *
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
import time

#os.environ['CUDA_VISIBLE_DEVICES'] = '2'
PNG_SIZE =28
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

command = "mono SplitCap.exe -r demo0.pcap -o Tinba -s flow -p 1017"
os.system(command)
time.sleep(0.4)

path = "/home/yzh/Desktop/FlowIdentification/Tinba/"
#path = "/home/yzh/Desktop/FlowIdentification/PcapSplit/demo0/"
# path = "/home/wyj/DeepTraffic-master/1.malware_traffic_classification/1.DataSet-USTC-TFC2016/PreCapture/Malware/demo/"
files = os.listdir(path)
filesSize = len(files)

malware_list = []
begnin_list = []
malware_path = ""
# t1 = timer()
model = load_model('./LeNet-5Of10MalwareFlowAllLayersClass.h5') #10分类恶意
# mnist_test = input_data_new.read_data_sets('/home/wyj/DeepTraffic-master/1.malware_traffic_classification/2.PreprocessedTools-USTC-TK2016/SplitOnePcaPcapSplitp/Nmap/mnist_dir')

# train_x = mnist.train.images
# train_x=np.reshape(train_x,(-1,28,28,1))

dict_10class_malware = {0:'Cridex',1:'Botnet',2:'Htbot',3:'Miuref',4:'SshAttack',5:'Dedrop',6:'Shifu',7:'Tinba',8:'Neris',9:'Nmap'}
print("over")   

# result = model.predict_classes(train_x)
# print(result[0:100])

for file in files:   
    # print(path+file)
    fh = getMatrixfrom_pcap(str(path+file), PNG_SIZE)
    #fh = getMatrixfrom_pcap(str("./SshAttack/FlowAllLayers/" + file), PNG_SIZE)
    im = Image.fromarray(fh)
    images = numpy.reshape(fh,(-1,28,28,1))
    images = images.astype(numpy.float32)
    images = numpy.multiply(images, 1.0 / 255.0)
#     print(images)
    result = model.predict_classes(images)
    malware_list.append(dict_10class_malware[result[0]])
    print(dict_10class_malware[result[0]])

print(malware_list)
