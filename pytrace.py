#!/usr/bin/env python

"""
	Attempting to mimic traceroute via Python basic sockets.
	2010.08.02 ( Ben )

"""
import socket, re, sys, time, select

if len(sys.argv) < 2:
	print "Please specify a file containing the addresses to trace."
	print "ex: %s /path/to/myfile.txt" % (sys.argv[0])
	exit(2)
elif len(sys.argv) > 2:
	print "%s accepts only one input parameter. Ignoring trailing parameters.\n\n"

fileloc = sys.argv[1]
infile = open(fileloc, 'rb')
sport = 33435
ttl, maxhops = (1, 30)
udp, icmp = (socket.getprotobyname("udp"), socket.getprotobyname("icmp"))

def senddgram(addr, port, ttl):
	ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
	ssock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
	ssock.sendto("", (addr, port))
	dgSent = time.time()
	""" ??? """
	ssock.close()
	return dgSent


def rcv_icmp(port, timeout=2):
	_tremain = timeout
	while True:
		_begin = time.time()
		rsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
		rsock.bind(("", port))
		_ready = select.select(rsock, [], [], _tremain)
		_topening = (time.time() - begin)
		if _ready[0] == []:
			return
		_trecvd = time.time()
		rpayload, addr = rsock.recvfrom(1024)
		_tremain = _tremain - _topening
		if _tremain <= 0:
			return
	delay = _trecvd - dgSent
	print "%d\t%s\t%dms" % (ttl, addr, delay)
	return addr


def main(dest, port):
	global ttl
	if re.search("\b(?:\d{1,3}\.){3}\d{1,3}\b", dest) == None:
		try:
			dst_addr = socket.gethostbyname(dest)
		except socket.error:
			print "Error resolving %s. Please try again with IP address." % (dest)
			exit(2)
	else:
		dst_addr = dest
		

	curraddr = None
	currhost = None
	try:
		senddgram(dest, port, ttl)
		curraddr = rcv_icmp(port)
	except socket.error:
		return

	ttl += 1
	if curraddr == dest or ttl > maxhops:
		print "%s - %d hops away" % (curaddr, ttl)

if __name__ == "__main__":
	#main(dst)
	for line in infile:
		main(line.split(" ")[0], sport)
		sport += 1
