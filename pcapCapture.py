import pcap
from PIL import Image
import binascii
import numpy
from keras.models import load_model
import os
import dpkt

model1 = load_model('./LeNet-5Of2Class.h5')
model2 = load_model('./LeNet-5Of10Class.h5') #10分类
dict_10class_malware = {0:'Cridex',1:'Geodo',2:'Htbot',3:'Miuref',4:'Neris',5:'Nsis-ay',6:'Shifu',7:'Tinba',8:'Wannacry',9:'Nmap',10:'Botnet',11:'Virut'}

# # list all of the Internet devices
# devs = pcap.findalldevs()
# print(*devs, sep='\n')

# pc = pcap.pcap(devs[4], promisc=True, immediate=True, timeout_ms=50)
# # fiter http pcakets
# pc.setfilter('src host 192.168.171.143 or dst host 192.168.171.143')
PNG_SIZE = 28
# def getMatrixfrom_pcap(content,width):
#     hexst = binascii.hexlify(content)
#     fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
#     if len(fh)<784:
#         x = numpy.zeros(784)
#         x[:len(fh)]=fh
#         fh = x
#     if len(fh)>784:
#         fh = fh[:784]
#     rn = int(len(fh)/width)
#     fh = numpy.reshape(fh[:(rn*width)],(-1,width))
#     fh = numpy.uint8(fh)
#     return fh

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

files = os.listdir("./PcapSplit/demo59/")
for file in files:   
    fh = getMatrixfrom_pcap(str('./PcapSplit/demo59/'+file), PNG_SIZE)
    im = Image.fromarray(fh)
    image = numpy.reshape(fh,(-1,28,28,1))
    result = model2.predict_classes(image)
    print(result)


# for ptime, pdata in pc:
#     print(ptime)
#     print(pc)
#     fh = getMatrixfrom_pcap(pdata, PNG_SIZE)
#     image = numpy.reshape(fh,(-1,28,28,1))
#     result = model1.predict_classes(image)
#     # print(result)
    
#     if result[0] == 1:
#         result = model2.predict_classes(image)
#         # print("\n")
#         # print(pdata)
#         print(dict_10class_malware[result[0]])
#         # print("\n")

    