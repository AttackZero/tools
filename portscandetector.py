from scapy.all import *
import sys
from datetime import datetime
import socket

# A map of the ICMP types and codes for more friendly output
# The tuples are set up as (type, code)
icmpCodes = { (0, 0): 'ICMP Echo Reply (Ping Reply)',
	      # Types 1 and 2 are reserved
	      (3, 0): 'Destination network unreachable',
	      (3, 1): 'Destination host unreachable',
	      (3, 2): 'Desination protocol unreachable',
	      (3, 3): 'Destination port unreachable',
	      (3, 4): 'Fragmentation required, Don\'t Fragment (DF) Flag Set',
	      (3, 5): 'Source route failed',
	      (3, 6): 'Destination network unknown',
	      (3, 7): 'Destination host unknown',
	      (3, 8): 'Source host isolated',
	      (3, 9): 'Network administratively prohibited',
	      (3, 10): 'Host administratively prohibited',
	      (3, 11): 'Network unreachable for TOS',
	      (3, 12): 'Host unreachable for TOS',
	      (3, 13): 'Communication administratively prohibited',
	      (3, 14): 'Host Precedence Violation',
	      (3, 15): 'Precendence cutoff in effect',
	      # Code (4, 0) is deprecated
	      (5, 0): 'Redirect Datagram for the Network',
	      (5, 1): 'Redirect Datagram for the Host',
	      (5, 2): 'Redirect Datagram for the TOS and network',
	      (5, 3): 'Redirect Datagram for the TOS and host',
	      # Type 6 is deprecated
	      # Type 7 is reserved
	      (8, 0): 'Echo / Ping Request',
	      (9, 0): 'Router advertisement',
	      (10, 0): 'Router discovery / selection / solicitation',
	      (11, 0): 'TTL expired in transit',
	      (11, 1): 'Fragment reassembly time exceeded',
	      (12, 0): 'Bad IP Header',
	      (12, 1): 'Bad IP Header: Missing a required option',
	      (12, 2): 'Bad IP Header: Bad length',
	      (13, 0): 'Timestamp',
	      (14, 0): 'Timestamp Reply'
	      # The rest are deprecated, reserved, or experiemental
	    }

# Figure out the IP address of the first non-lo interface
localIPAddr = socket.gethostbyname(socket.gethostname())

# Ports to listen for
# The line below listens for selected ports, the commented out line
# listens for all ports
tcpPorts = [ 80, 443, 3389, 3306, 1433, 5900, 445, 135 ]
#tcpPorts = [ x for x in range(0, 65536) ]

udpPorts = [ x for x in range(0, 65536) ]

# Filters do not work too well on VM interfaces, so we will build a filter
# lfilters are python functions that apply to each packet

'''
If a filter function returns True, that means the packet
met whatever conditions were specified.  If the packet did
not meet specified conditions, then we return False.
'''
def build_lfilter(pkt):
	# Exclude packets that come from this machine
	if IP in pkt:
		if pkt[IP].src == localIPAddr:
			return False

	if TCP in pkt and pkt[TCP].dport in tcpPorts:
		return True
	elif UDP in pkt and pkt[UDP].dport in udpPorts:
		return True
	elif ICMP in pkt:
		return True
	else:
		return False

'''
This function outputs basic information about the packet.

If you wanted to do something more than print to the screen
(like write to a log or send an e-mail, you could do that
here instead.
'''
def parsePacket(pkt):
	currentTime = datetime.now().strftime('%Y-%m-%d %H:%M')
	if IP in pkt:
		sourceAddr = pkt[IP].src
		destAddr = pkt[IP].dst
	else:
		print('[{0}] Packet not an IP packet'.format(currentTime))
		return

	if TCP in pkt:
		sourcePort = pkt[TCP].sport
		destPort = pkt[TCP].dport
		print('[{0}] [TCP] {1}:{2} -> {3}:{4}'.format(currentTime, sourceAddr, sourcePort, destAddr, destPort))
	elif UDP in pkt:
		sourcePort = pkt[UDP].sport
		destPort = pkt[UDP].dport
		print('[{0}] [UDP] {1}:{2} -> {3}:{4}'.format(currentTime, sourceAddr, sourcePort, destAddr, destPort))
	elif ICMP in pkt:
		type = pkt[ICMP].type
		code = pkt[ICMP].code
		typeCodeString = icmpCodes.get((type, code))
		print('[{0}] [ICMP Type {1}, Code {2}: {3}] {4} -> {5}'.format(currentTime, type, code, 
										typeCodeString if typeCodeString else '',
										sourceAddr, destAddr))
	
	return

while True:
	'''
	prn is called to process each packet
	count = 0 means sniff an unlimited number of packets
	'''
	try:
		sniffer = sniff(lfilter=build_lfilter, count=0, prn=parsePacket)
		# If we Ctrl-C, then exit
		sys.exit()
	except socket.error:
		print('This script must be run as root / Administrator.  Exiting...')
		sys.exit()
