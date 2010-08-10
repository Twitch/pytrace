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
max_hops = 30
timeout = 5
target = sys.argv[1]
s_port = 33375
ttl = 0

def opensocks(port):
	global icmp_sock
	global udp_sock
	icmp,udp = socket.getprotobyname('icmp'), socket.getprotobyname('udp')
	icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
	udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

def send_probe(dst, port, ttl):
	udp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
	udp_sock.sendto("", (dst, port))
	sent = time.time()
	return sent

def recv_icmp(port):
	icmp_sock.bind(("", port))
	begin = time.time()
	wait = timeout
	while True:
		rd, wr, err = select.select([icmp_sock], [], [], wait)
		if rd:
			try:
				reply, src = icmp_sock.recvfrom(1024)
			except socket.error:
				pass
			if reply:
				if ord(reply[20]) == 8 or ord(reply[20]) == 0: # ECHO packets, none of our business.
					pass
				elif ord(reply[20]) == 11 or ord(reply[20]) == 3: # TTL_Exceeded or DST_Unreachable
					received = time.time()
					return reply, received, src
				else:
					print "\t\t Unexpected ICMP header type \n%s" % reply
					exit(2)
		wait = (begin + timeout) - time.time()
		if wait < 0:
			return None, None, None

def clsocks():
	icmp_sock.close()
	udp_sock.close()

def execute(port, target, ttl):
	ttl += 1	
	opensocks(port)
	t_sent = send_probe(target, port, ttl)
	t_recv = recv_icmp(port)
	clsocks()
	if t_recv == None:
		print "%d\t*no reply*\t***" % (ttl)
	else:
		elapsed = (t_recv[1] - t_sent) * 1000.0
		print "%d\t%s\t%0.3f ms" % (ttl, t_recv[2][0], elapsed) 
	if ttl > max_hops:
		print "Max hops (30) reached."
		exit(2)
	if target != t_recv[2][0]:
		execute(port, target, ttl)


execute(s_port, target, ttl)
