import random
import dpkt
import socket

fileSize = 10000*1

scan_list = ['Cridex', 'Botnet', 'Htbot', 'Miuref', 'SshAttack', 'Dedrop', 'Shifu', 
			'Tinba', 'Neris', 'Nmap']			
for scan in scan_list:
	# print(scan)
	scan_file = './Pcap/Malware/' + scan + '.pcap'

	mingle_file_1 = 'InsertPcap/' + scan + '_1.pcap'
	mingle_file_2 = 'InsertPcap/' + scan + '_0.1.pcap'
	mingle_file_3 = 'InsertPcap/' + scan + '_0.01.pcap'
	mingle_file_4 = 'InsertPcap/' + scan + '_0.001.pcap'
	# mingle_file_5 = 'InsertPcap/' + scan + '_0.0001.pcap'
	pcap_mingle_1 = dpkt.pcap.Writer(open(mingle_file_1, 'wb'))
	pcap_mingle_2 = dpkt.pcap.Writer(open(mingle_file_2, 'wb'))
	pcap_mingle_3 = dpkt.pcap.Writer(open(mingle_file_3, 'wb'))
	pcap_mingle_4 = dpkt.pcap.Writer(open(mingle_file_4, 'wb'))
	# pcap_mingle_5 = dpkt.pcap.Writer(open(mingle_file_5, 'wb'))
	pcap_clean = dpkt.pcap.Reader(open('./Pcap/Benign/FTP.pcap', 'rb')).readpkts()
	pcap_scan = dpkt.pcap.Reader(open(scan_file, 'rb')).readpkts()
	# pcap_scan = []
	
	# pre-execution
	# for ts, buf in scan:
		# temp = buf[:26]
		# temp += socket.inet_aton('192.168.159.130')
		# temp += socket.inet_aton('192.168.159.128')
		# temp += buf[34:]
		# pcap_scan.append([ts, bytes(temp)])
			
	# percent 100%
	print('100%')
	s = pcap_scan[:]
	count = 0
	for ts, buf in s:
		# temp = buf[:26]
		# temp += socket.inet_aton('192.168.159.130')
		# temp += socket.inet_aton('192.168.159.128')
		# temp += buf[34:]
		# pcap_mingle_1.writepkt(bytes(temp), ts=ts)
		pcap_mingle_1.writepkt(bytes(buf), ts=ts)
		count = count + 1
		if count >= fileSize:
			break

	pcap_mingle_1.close()
	
	# percent 10%
	print('10%')
	count = 0
	print(len(pcap_scan))
	print(fileSize/10)
	if len(pcap_scan)>=fileSize/10:
		print("len(pcap_scan)<=fileSize/10")
		s = pcap_scan[:int(fileSize/10)]
	else:
		s = pcap_scan

	if len(pcap_clean)>=(fileSize-fileSize/10):
		print("len(pcap_clean)<=(fileSize-fileSize/10)")
		c = pcap_clean[:int(fileSize-fileSize/10)]
	else:
		c = pcap_clean
		
	# sum = 0
	total = len(s)
	i = 0
	for ts, buf in c:
		# sum += len(buf)
		# temp = buf[:26]
		# temp += socket.inet_aton('192.168.159.130')
		# temp += socket.inet_aton('192.168.159.128')
		# temp += buf[34:]
		# pcap_mingle_2.writepkt(bytes(temp),ts=ts)
		pcap_mingle_2.writepkt(bytes(buf),ts=ts)

		for r in range(5):
			if i < total and random.random() < 0.5:
				pcap_mingle_2.writepkt(s[i][1], ts=s[i][0])
				i += 1

	pcap_mingle_2.close()
	print(i==total)
	

	# percent 1%
	print('1%')
	count = 0
	print(len(pcap_scan))
	print(fileSize/100)
	if len(pcap_scan)>=fileSize/100:
		print("len(pcap_scan)<=fileSize/100")
		s = pcap_scan[:int(fileSize/100)]
	else:
		s = pcap_scan

	if len(pcap_clean)>=(fileSize-fileSize/100):
		print("len(pcap_clean)<=(fileSize-fileSize/10)")
		c = pcap_clean[:int(fileSize-fileSize/100)]
	else:
		c = pcap_clean
		
	# sum = 0
	total = len(s)
	i = 0
	for ts, buf in c:
		# sum += len(buf)
		# temp = buf[:26]
		# temp += socket.inet_aton('192.168.159.130')
		# temp += socket.inet_aton('192.168.159.128')
		# temp += buf[34:]
		# pcap_mingle_2.writepkt(bytes(temp),ts=ts)
		pcap_mingle_3.writepkt(bytes(buf),ts=ts)

		for r in range(5):
			if i < total and random.random() < 0.5:
				pcap_mingle_3.writepkt(s[i][1], ts=s[i][0])
				i += 1

	pcap_mingle_3.close()
	print(i==total)

	# percent 0.1%
	print('0.1%')
	count = 0
	print(len(pcap_scan))
	print(fileSize/1000)
	if len(pcap_scan)>=fileSize/100:
		print("len(pcap_scan)<=fileSize/1000")
		s = pcap_scan[:int(fileSize/1000)]
	else:
		s = pcap_scan

	if len(pcap_clean)>=(fileSize-fileSize/1000):
		print("len(pcap_clean)<=(fileSize-fileSize/1000)")
		c = pcap_clean[:int(fileSize-fileSize/1000)]
	else:
		c = pcap_clean
		
	# sum = 0
	total = len(s)
	i = 0
	for ts, buf in c:
		# sum += len(buf)
		# temp = buf[:26]
		# temp += socket.inet_aton('192.168.159.130')
		# temp += socket.inet_aton('192.168.159.128')
		# temp += buf[34:]
		# pcap_mingle_2.writepkt(bytes(temp),ts=ts)
		pcap_mingle_4.writepkt(bytes(buf),ts=ts)

		for r in range(5):
			if i < total and random.random() < 0.5:
				pcap_mingle_4.writepkt(s[i][1], ts=s[i][0])
				i += 1

	pcap_mingle_4.close()
	print(i==total)
