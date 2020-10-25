# Rat Poison

## Team Members
Patrick Kang Wei Sheng <br/>
Jerome Tan Kian Wei <br/>
Kevin Tan<br/><br/>


### Usage
 
python poison.py -h                 // Help Menu 

python poison.py -l 192.168.1.0/24  // Shows all active host within the local network using ARP Broadcast

python poison.py --stealth          // Prevents host machine from being discovered <br/><br/>

<To be used with -T, -M, -G, -TM, -MM, -GM> </br>

-P                                   // ARP poisoning mode without VLAN double tagging

-PV                                  // ARP poisoning mode with VLAN double tagging <br/><br/><br/>

-T 192.168.10.10                     // Specify target’s IP address

-M 192.168.10.11                     // Specify monitoring PC IP address

-G 192.168.10.1                      // Specify gateway/target2 IP address

-TM “AA:AA:AA:AA:AA:AA”              // To specify target’s MAC address

-MM “BB:BB:BB:BB:BB:BB”              // Specify monitoring PC MAC address

-GM “CC:CC:CC:CC:CC:CC”              // Specify gateway/target2 MAC address

--vlan1 10                           // To specify the first Dot1Q VLAN number

--vlan2 20                           // To specify second Dot1Q VLAN number

                                                 
