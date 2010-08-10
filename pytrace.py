#!/usr/bin/env python

"""
	Attempting to mimic traceroute via Python basic sockets.
	2010.08.02 ( Ben )

"""
import socket, re, sys, time, select, threading as th

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

#class traceroute(th.Thread):
class traceroute():
	def __init__(self, host, sport):
		self.max_hops = 10
		self.target = host
		self.port = sport
		self.timeout = 2
		self.ttl = 0
		#th.Thread.__init__ (self)
	
	def send_probe(self):
		self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 17)
		self.udp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
		try:
			self.udp_sock.sendto("", (self.target, self.port))
		except socket.error:
			return False
		self.sent = time.time()
		self.udp_sock.close()

	def recv_icmp(self):
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
				if self.reply:
					if ord(self.reply[20]) == 8 or ord(self.reply[20]) == 0: # ECHO packets, none of our business.
						pass
					elif ord(self.reply[20]) == 11 or ord(self.reply[20]) == 3: # TTL_Exceeded or DST_Unreachable
						self.received = time.time()
						self.udp_sock.close()
						return True
					else:
						print "\t\t Unexpected ICMP header type \n%s" % reply
						exit(2)
			wait = (begin + self.timeout) - time.time()
			if wait < 0:
				self.udp_sock.close()
				return None

	def execute(self):
		self.ttl += 1
		t_sent = self.send_probe()
		t_recv = self.recv_icmp()
		if t_recv == None:
			print "%d\t*no reply*\t***" % (self.ttl)
		else:
			elapsed = (self.received - self.sent) * 1000.0
			self.lasthost = {"hop" : self.ttl, "addr" : self.src, "ping" : elapsed}
			print "%d\t%s\t%0.3f ms" % (self.ttl, self.src[0], elapsed) 
		if self.ttl >= self.max_hops:
			print "Max hops (%d) reached." % self.max_hops
			targets.append(self.lasthost)
			exit(2)
		if self.target != self.src:
			self.execute()
		else:
			hosts.append(self.lasthost)
	
	def run(self):
		self.execute()
	

#traceroute(host, s_port).start()

narf = traceroute(host, s_port).run()
