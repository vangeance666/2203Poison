import sys
import pydivert

try:
	with pydivert.WinDivert("tcp.DstPort != 0") as w:
	    for packet in w:
	    	print(packet)
	    	# print(packet.payload)
	        # if packet.dst_port == 1234:
	        #     print(">") # packet to the server
	        #     packet.dst_port = 80
	        # if packet.src_port == 80:
	        #     print("<") # reply from the server
	        #     packet.src_port = 1234
	        # w.send(packet)
except KeyboardInterrupt:
	sys.exit(2)