#!/usr/bin/env python

"""
   Attempting to mimic traceroute via Python basic sockets.
	2010.08.02 ( Ben )
"""

import socket, re, sys, threading as th

dst = sys.argv[1]



def main(dest):
	if re.search("\b(?:\d{1,3}\.){3}\d{1,3}\b", dest) == None:
		print "Attempting to resolve %s..." % (dest)
		try:
			dst_addr = socket.gethostbyname(dest)
		except socket.error:
			print "Error resolving %s. Please try again with IP address." % (dest)
			exit(2)
		print "Resolved to %s" % (dst_addr)
	else:
		dst_addr = dest
		
	udp, icmp = (socket.getprotobyname("udp"), socket.getprotobyname("icmp"))
	ttl, port, maxhops = (1, 33444, 30)

	while True:
		rsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
		ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
		ssock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

		rsock.bind(("", port))
		ssock.sendto("", (dest, port))
		
		curraddr = None
		currname = None
		try:
			_, curraddr = rsock.recvfrom(512)
			curraddr = curraddr[0]
			try:
				currname = socket.gethostbyaddr(curraddr)[0]
			except socket.error:
				currname = curraddr

		except socket.error:
			pass
		finally:
			ssock.close()
			rsock.close()

		if curraddr is not None:
			currhost = "%s (%s)" % (currname, curraddr)
		else:
			currhost = "*"
		print "%d\t%s" % (ttl, currhost)

		ttl += 1
		if curraddr == dest or ttl > maxhops:
			break

if __name__ == "__main__":
	main(dst)
