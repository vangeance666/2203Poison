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
	
	# res = arping("192.168.10.*")
	# 
	# 
	t_ip = "192.168.20.10"
	t_mac = "ec:f4:bb:60:3e:86"
	m_ip = "192.168.20.11"
	m_mac = "ec:f4:bb:60:3e:42"

	gw_ip = "192.168.20.1"
	gw_mac = "00-c8-8b-6d-f8-42"


	BRDCAST = "ff:ff:ff:ff:ff:ff"



	# target 192.168.10.10


	# - hwsrc is the MAC corresponding to psrc, to update in the target's arp table
	# - pdst is where the ARP packet should go (target),
	# - psrc is the IP to update in the target's arp table,
	# - hwdst is the destination hardware address
	
	ether = Ether()
	dot1q1 = Dot1Q(vlan=10)
	dot1q2 = Dot1Q(vlan=20)
	
	# arp = ARP(hwdst=t_mac, hwsrc=fake_mac, pdst=target_ip, psrc=fake_ip, op="is-at")


	arp = ARP(hwsrc=m_mac, pdst=t_ip, psrc=m_ip, op=2)

	# pkt2 = Ether(dst=BRDCAST)/Dot1Q(vlan=10)/Dot1Q(vlan=20)/ARP(hwdst=t_mac, hwsrc=m_mac, pdst=t_ip, psrc=m_ip, op=2)/IP(dst=t_ip)
	# pkt2.show()
	# # exit()
	# i=0
	# try :
	# 	while 1:
	# 		if i == 1000:
	# 			exit()
	# 		sendp(pkt2)
	# 		# send(Ether(dst=BRDCAST)/Dot1Q(vlan=10)/Dot1Q(vlan=20)/ARP(hwdst=t_mac, hwsrc=m_mac, pdst=t_ip, psrc=m_ip, op=2))
	# 		i+=1

	# except KeyboardInterrupt:
	# 	sys.exit()

	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),timeout=2)
	for x in ans:
		print(x)
	# ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )

	# for i in range (10):
	# 	send(packet ,inter=RandNum(10,40), loop=1)
	
	# pkt = Ether()/Dot1Q(vlan=10)/Dot1Q(vlan=20)/ARP()

	# pkt.show()

	# PKT_poison_1 = ARP(op=2, hwdst=target_mac, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=monitor_mac)

	# self._double_tag_packet(self.PKT_poison_1)


	# ans, unans = sr(IP(dst="192.168.20.1-12")/ICMP())
	# ans.summary(lambda s,r: r.sprintf("%IP.src% is alive") )
	# for a in ans:
	# 	a.show()

	# pkts = sniff(iface="Killer(R) Wi-Fi 6 AX1650s 160MHz Wireless Network Adapter (201D2W)", count=1000)
	# for p in pkts:
	# 	p.show()
	
	# print(get_if_addr(conf.iface))




