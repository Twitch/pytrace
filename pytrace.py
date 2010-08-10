#!/usr/bin/env python

"""
	Attempting to mimic traceroute via Python basic sockets.
	2010.08.02 ( Ben ) -- Began
	2010.08.10 ( Ben ) -- Last Update

"""
import socket, sys, time, select, binascii

# Simple input validation
if len(sys.argv) < 2:
   print "Please specify a file containing the addresses to trace."
   print "ex: %s /path/to/myfile.txt" % (sys.argv[0])
   exit(2)
elif len(sys.argv) > 2:
   print "%s accepts only one input parameter. Ignoring trailing parameters.\n\n"

""" Defines """
s_port = 33375
host = sys.argv[1]
targets = []

class traceroute():
	def __init__(self, host, sport):
		#Set internal class variables.
		self.max_hops = 30
		self.target = host
		self.port = sport
		self.timeout = 2
		self.ttl = 0
		self.max_noreply = 5
		self.noreply = 0
	
	def send_probe(self):
		#Open UDP socket and send probe packet. ret False on socket error.
		self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 17)
		self.udp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
		try:
			self.udp_sock.sendto("", (self.target, self.port))
		except socket.error:
			return False
		self.sent = time.time()
		self.udp_sock.close()

	def recv_icmp(self):
		#Open socket to receive ICMP errors.
		self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
		self.icmp_sock.bind(("", self.port))
		begin = time.time()
		wait = self.timeout
		while True:
			rd, wr, err = select.select([self.icmp_sock], [], [], wait)
			if rd:
				try:
					self.reply, self.src = self.icmp_sock.recvfrom(1024)
				except socket.error:
					pass
				if self.reply: # Data received.
					r_port = int(str(binascii.hexlify(self.reply[50:52])), 16) # Dport from returned UDP packet.
					if r_port != self.port:
						# Make sure this ICMP is for our probe.
						pass
					else:
						self.itype = ord(self.reply[20])
						if self.itype == 8 or self.itype == 0 or self.itype == 3:
							# ECHO or unreachable packets, not interested.
							pass
						elif self.itype == 11:
							# TTL_Exceeded
							self.received = time.time()
							self.udp_sock.close()
							return True
						else:
							# Other ICMP types. Do whatever. Exit for now to debug.
							print "\tUnexpected ICMP type\n%s from %s for tracing %s" % (reply, self.src, self.target)
							exit(2)
			wait = (begin + self.timeout) - time.time()
			if wait < 0: # Timeout expired.
				self.udp_sock.close()
				return None

	def execute(self):
		self.ttl += 1
		self.send_probe()
		t_recv = self.recv_icmp()
		if t_recv == None:
			self.noreply += 1
			""" Timed out """
			print "%d\t*no reply*\t***" % (self.ttl)
		else:
			""" Response received, set new lasthop in case we time out later """
			self.noreply = 0
			elapsed = (self.received - self.sent) * 1000.0
			self.lasthost = {"hop" : self.ttl, "addr" : self.src[0], "ping" : elapsed, "dest" : self.target}
			print "%d\t%s\t%0.3f ms\t%d" % (self.ttl, self.src[0], elapsed, self.itype) 
		
		if self.noreply >= self.max_noreply:
			print "\tMaximum number of orphaned probes sent. Terminating."
			targets.append(self.lasthost)
			return None
		if self.ttl >= self.max_hops:
			print "Max hops (%d) reached." % self.max_hops
			targets.append(self.lasthost)
			return None
		if self.target != self.src:
			# Have no arrived at destination. 
			self.execute()
		else:
			targets.append(self.lasthost)
			return None
	
	def run(self):
		self.execute()
	


try:
	f = open(sys.argv[1])
	for l in f:
		host = l.split(" ")[0]
		narf = traceroute(host, s_port).run()
		s_port = s_port + 1

	print "##########################"
	print "##\t Targets \t##"
	print "##########################"
	print "\tTarget\t\t|\tHops\t|\tLast Hop\t|\tDelay"
	for t in targets:
		print "\t%s\t|\t%d\t|\t%s\t|\t%0.3f ms" % (t["dest"], t["hop"], t["addr"], t["ping"])

except KeyboardInterrupt:
	print "\nSIGINT received. Terminating... with extreme prejudice."
	print targets
	exit(2)
