from scapy.all import *



def show_all_network_interfaces(resolve_mac=True):
	IFACES.show(resolve_mac)



def show_all_routes(clean=True):
	if clean:
		pass
	conf.route.resync()
	print(conf.route)

def get_all_routes():
	conf.route.resync()
	return conf.route

def main():

	# get_interfaces()
	# show_all_network_interfaces(False)
	# get_network_details("192.168.1.0/24")	
	# show_all_routes()
	# show_all_net_ifaces()
	
	# print(_get_network_address("192.168.1.148", "255.255.255.0"))
	ScapyUtility.get_network_details("192.168.1.0")

	# print(_get_mac_from_ip("192.168.1.145"))





if __name__ == '__main__':
	# - hwsrc is the MAC corresponding to psrc, to update in the target's arp table
	# - pdst is where the ARP packet should go (target),
	# - psrc is the IP to update in the target's arp table,
	# - hwdst is the destination hardware address
	
	# pk1 = Ether()
	# pk1.show()
	# pkt = Ether()/ARP(op=2, pdst="192.168.1.10", psrc="192.168.1.30", hwsrc="18:9c:5d:5e:7f:c0")
	# pkt.show()
	# print(pkt.summary())
	
	pkts = sniff(iface="Killer(R) Wi-Fi 6 AX1650s 160MHz Wireless Network Adapter (201D2W)", count=1000)
	for p in pkts:
		p.show()
	
	# print(get_if_addr(conf.iface))




