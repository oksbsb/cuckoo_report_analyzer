import parser.json_parser as jp
import analyzer.analyzer as analyzer


import sys
import ipapi
import hashlib
import os
import virustotal
import dpkt
import socket
import datetime
import hexdump
import sys

def main():
	F_NAME = ""
	jp.report(sys.argv[1])
	F_NAME = jp.get_file_name()

	analyzer.set_file(F_NAME)	
	analyzer.main()

if __name__ == "__main__":
	#memanggil fungsi main
	main()
	# data_reader.read_csv()

	
            





	

    