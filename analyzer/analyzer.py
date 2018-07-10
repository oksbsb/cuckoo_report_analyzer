import dataset.data_reader as data_reader

import json
import sys
import ipapi
from pandas.io.json import json_normalize
import hashlib
from termcolor import colored
import os
import virustotal
import dpkt
import socket
import datetime
import hexdump
import sys

VT_API_KEY = "c6897aa50129b40c32139ed2ebe53214139eeb9068f87b43584e6016eb853932"
F_NAME = ""

def set_file(filename):
	global F_NAME
	F_NAME = filename

def get_file():
	global F_NAME
	return F_NAME	

def load_process_data():
	with open("./storage/"+get_file()+"/processes.json", 'r') as f:
		processes_dict = json.load(f)
	return processes_dict

def load_pe_imports_data():
	with open("./storage/"+get_file()+"/pe_imports.json", 'r') as f:
		processes_dict = json.load(f)
	return processes_dict

def load_info():
	with open("./storage/"+get_file()+"/executable_info.json", 'r') as f:
		info_dict = json.load(f)
	return info_dict


def virus_total_report(md5):
	v = virustotal.VirusTotal(VT_API_KEY)
	report = v.get(md5)
	print "Report"
	print "- Resource's UID:", report.id
	print "- Scan's UID:", report.scan_id
	print "- Permalink:", report.permalink
	print "- Resource's SHA1:", report.sha1
	print "- Resource's SHA256:", report.sha256
	print "- Resource's MD5:", report.md5
	print "- Resource's status:", report.status
	print "- Antivirus' total:", report.total
	print "- Antivirus's positives:", report.positives
	for antivirus, malware in report:
	    if malware is not None:
	        print
	        print "Antivirus:", antivirus[0]
	        print "Antivirus' version:", antivirus[1]
	        print "Antivirus' update:", antivirus[2]
	        print "Malware:", malware


def comparing(first_seq,second_seq,malware_seq):
	score = 0
	position = 0
	array = []
	count = 0


	for data in first_seq:
		
		if count == 1000:
			break
		for dat in data:

			for da in second_seq:	
				if (da==dat):

					score+=1
				if da in malware_seq:
					print malware_seq

		array.append((data[0],score))
		score = 0
		count += 1


	min_val = 0
	max_scored_element = None

	count = 0
	for data in array:
		print data
		if data[1] > min_val:
			#menandai posisi maximum score
			position = count
			
			max_scored_element = data
			min_val = data[1] 
		count+=1

	print max_scored_element
	check_API(first_seq[position],second_seq)

def check_API(first_seq,second_seq):
	count = 0

	for data in first_seq:
		print data
		if data in second_seq:
			count += 1
			print (data,count)


# def read_memory_dump():
# 	data = []
# 	with open('../source_files/memory.dmp', 'rb') as infile:
# 		while True:
# 			data.append(infile.read(204800))
# 			print hexdump.hexdump(data)
# 			if not data:
# 				break





def main():
	processes = load_process_data()

	api_calls = []

	print processes
	calls = processes['calls']

	for call in calls:
		api_calls.append(call['api'])
		
	dlls =[]
	pe_imports = load_pe_imports_data()
	for pe_import in pe_imports:
		print pe_import['dll']
		for imports in pe_import['imports']:
			print imports['name']
			dlls.append((pe_import['dll'],imports['name']))

	sha1 = ""
	sha256 = ""
	sha512 = ""
	md5 = ""		

	infos = load_info()
	for info in infos:
		print '==='
		print info 
		print infos[info]
		sha1 = infos['sha1']
		sha256 = infos['sha256']
		sha512 = infos['sha512']
		md5 = infos['md5']


	first_seq = data_reader.read_csv()

	second_seq = api_calls
	
	malware_seq = data_reader.read_csv_malware_API()

	comparing(first_seq,second_seq,malware_seq)

	# virus_total_report(md5)





	

    