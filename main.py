import parser.json_parser as jp
import parser.pcap_parser as pp
import analyzer.analyzer as analyzer

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

	
            





	

    