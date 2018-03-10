from scapy.all import *
import sys
import random
import subprocess
import argparse

default_target_domain = 'icanhazip.com'
default_dns_server = '8.8.8.8'

parser = argparse.ArgumentParser(description='Perform HTTP GET request with Scapy.')
parser.add_argument('--target','-t', action="store", default=default_target_domain, help='Specify HTTP Target domain: default=%s'%default_target_domain)
parser.add_argument('--dns','-d', action="store", default=default_dns_server, help='Specify DNS server to use for lookup: default=%s'%default_dns_server)
args = parser.parse_args()


def dnsLookup(target_domain,dns_server):
	dns_forwarder = dns_server
	question = DNSQR(qname=target_domain)
	dns_query = IP(dst=dns_forwarder)/UDP(dport=53)/DNS(qr=0, rd=1, ad=1, qd=question)
	print "!!! Requesting DNS lookup for %s" % target_domain
	print dns_query.sprintf('\033[1m\033[94m>>>\033[0m %IP.dst%    DNS Q:    qd='+dns_query[DNSQR].qname+'    qr=%DNS.qr%    rd=%DNS.rd%    ad=%DNS.ad%')
	dns_response = sr1(dns_query)
	print "!!! Received DNS answer from DNS Servers %s" % dns_forwarder
	print dns_response.sprintf('%IP.dst% \033[1m\033[91m<<<\033[0m    DNS A:    rdata='+dns_response[DNSRR].rdata)
	answer = dns_response[DNSRR].rdata
	my_ip = dns_response[IP].dst
	print "!!! Determined our internal IP is %s" % my_ip
	print "\n\n"
	return (answer,my_ip)

def initSYN(pktIP,srcPort,dstPort,orig_seq_num):
	print "!!! Sending SYN"
	this_seq_num = orig_seq_num
	this_ack_num = 0
	print "\033[1mseq = our choice\033[0m"
	print "\033[1mack = 0\033[0m"
	syn = pktIP / TCP(sport=srcPort, dport=dstPort, seq=this_seq_num, ack=this_ack_num, flags='S')
	print syn.sprintf('\033[1m\033[94m>>>\033[0m %IP.dst%    %TCP.flags%:    seq=\033[1m\033[92m%TCP.seq%\033[0m    ack=\033[1m\033[35m%TCP.ack%\033[0m')
	syn_ack = sr1(syn)
	print "\033[1mseq = other parties choice\033[0m"
	print "\033[1mack = last-seq-num + 1\033[0m"
	print syn_ack.sprintf('%IP.dst% \033[1m\033[91m<<<\033[0m    %TCP.flags%:    seq=\033[1m\033[35m%TCP.seq%\033[0m    ack=\033[1m\033[92m%TCP.ack%\033[0m\n')
	return syn_ack

def initACK(pktIP,srcPort,dstPort,last_seq_num,last_ack_num):
	print "!!! Responding with ACK"
	this_seq_num = last_ack_num
	this_ack_num = last_seq_num+1
	print "\033[1mseq = last-ack-num\033[0m"
	print "\033[1mack = last-seq-num + 1\033[0m"
	ack = pktIP/ TCP(sport=srcPort, dport=dstPort, seq=this_seq_num, ack=this_ack_num, flags='A')
	print ack.sprintf('\033[1m\033[94m>>>\033[0m %IP.dst%    %TCP.flags%:    seq=\033[1m\033[92m%TCP.seq%\033[0m    ack=\033[1m\033[35m%TCP.ack%\033[0m\n')
	send(ack)
	return ack

def pshACK(pktIP,srcPort,dstPort,last_seq_num,last_ack_num,http_payload):
	print "!!! Sending HTTP GET via PSH-ACK"
	this_seq_num = last_seq_num
	this_ack_num = last_ack_num
	print "\033[1mseq = last_seq_num\033[0m"
	print "\033[1mack = last_ack_num\033[0m"
	http_request = pktIP/ TCP(sport=srcPort, dport=dstPort, seq=this_seq_num, ack=this_ack_num, flags='PA') / http_payload
	print http_request.sprintf('\033[1m\033[94m>>>\033[0m %IP.dst%    %TCP.flags%:    seq=\033[1m\033[92m%TCP.seq%\033[0m    ack=\033[1m\033[35m%TCP.ack%\033[0m   '), "len=%s"%len(http_payload)
	print '\033[1m\033[94m>>>\033[0m PAYLOAD: %s' % http_request.sprintf('%TCP.payload%').replace('\n','\n\t')
	http_reply = sr(http_request,multi=2,timeout=1)
	ans,unans = http_reply
	result = None
	if len(ans) >= 1:
		if len(ans[0]) >= 2:
			i = 0
			while i < len(ans):
				response = ans[i][1]
				if response.sprintf('%TCP.flags%') == 'A':
					pass
				elif response.sprintf('%IP.src%') != pktIP.dst:
					pass
				elif len(response[TCP].payload) > 3:
					print "\033[1mseq = last_ack_num\033[0m"
					print "\033[1mack = last_seq_num + last-pkt-len(%s)\033[0m" % len(http_payload)
					print response.sprintf('%IP.dst% \033[1m\033[91m<<<\033[0m    %TCP.flags%:    seq=\033[1m\033[35m%TCP.seq%\033[0m    ack=\033[1m\033[92m%TCP.ack%\033[0m')
					result = response
					break
				else:
					print "!!! Unexpected response"
					print response.sprintf('\n%IP.dst% \033[1m\033[91m<<<\033[0m    %TCP.flags%:    seq=\033[1m\033[35m%TCP.seq%\033[0m    ack=\033[1m\033[92m%TCP.ack%\033[0m\n')
				i+=1
		else:
			result = None
	else:
		result = None
	return result

def closeFINACK(pktIP,srcPort,dstPort,last_seq_num,last_ack_num,last_len_num):
	print "!!! Closing with FIN-ACK"
	this_seq_num = last_ack_num
	this_ack_num = last_seq_num+last_len_num+1
	print "\033[1mseq = last-ack-num\033[0m"
	print "\033[1mack = last-seq-num + last-pkt-len(%s) + 1\033[0m" %last_len_num
	fin_ack = pktIP / TCP(sport=srcPort, dport=dstPort, seq=this_seq_num ,ack=this_ack_num, flags='FA')
	print fin_ack.sprintf('\033[1m\033[94m>>>\033[0m %IP.dst%    %TCP.flags%:    seq=\033[1m\033[92m%TCP.seq%\033[0m    ack=\033[1m\033[35m%TCP.ack%\033[0m')
	closing_ack = sr1(fin_ack)
	print "\033[1mseq = last-ack-num\033[0m"
	print "\033[1mack = last-seq-num + 1\033[0m"
	print closing_ack.sprintf('%IP.dst% \033[1m\033[91m<<<\033[0m    %TCP.flags%:    seq=\033[1m\033[35m%TCP.seq%\033[0m    ack=\033[1m\033[92m%TCP.ack%\033[0m\n')
	return closing_ack




def main(target_domain,dns_server):
	# Set HTTP port
	dstPort = 80
	# DNS lookup for target_domain
	target_ip, my_ip = dnsLookup(target_domain,dns_server)

	# Fix client-side RST issue:
	# # Scapy uses user space to send packets to destination
	# # When the destination responds the client-side kernel drops packets
	# # because it wasn't expecting them, not in state table?
	# # This fix tells iptables to drop RST packets sent by the kernel
	try:
		subprocess.call('iptables -A OUTPUT -p tcp --tcp-flags RST RST -s %s -j DROP' % my_ip,shell=True)
	except Exception as e:
		print "Is iptables installed? %s" % str(e)
		sys.exit(1)

	# Random source port
	srcPort=random.randint(1024,65535)
	# Random starter TCP sequence number
	orig_seq_num = random.randint(0,( 2**32-1))
	# Constructing Scapy IP() used for all future packets
	pktIP = IP(dst=target_ip,src=my_ip)
	# HTTP GET payload with headers
	http_payload = """GET / HTTP/1.1\r
Host: %s\r
User-Agent: Python-Scapy\r
Accept: */*\r
Connection: keep-alive\r
X-SECURITY: Hello World, this is my HTTP GET request I've crafted it myself!\r
\r
""" % target_domain

	try:
		# Open with SYN
		syn_ack = initSYN(pktIP,srcPort,dstPort,orig_seq_num)
		# Respond to SYN-ACK with ACK
		ack = initACK(pktIP,srcPort,dstPort,syn_ack[TCP].seq,syn_ack[TCP].ack)
		# Send HTTP GET
		http_res = pshACK(pktIP,srcPort,dstPort,ack[TCP].seq,ack[TCP].ack,http_payload)
		# Print HTTP response
		print '\033[1m\033[91m<<<\033[0m PAYLOAD: %s' % http_res.sprintf('%TCP.payload%\n').replace('\n','\n\t')
		# Close connection gracefully with FIN-ACK
		closing_ack = closeFINACK(pktIP,srcPort,dstPort,http_res[TCP].seq,http_res[TCP].ack,len(http_res[TCP].payload))
	except Exception as e:
		print "Uhoh something went wrong :("
		print str(e)
		sys.exit(1)
	finally:
		print "Finished. Exiting."
	sys.exit(0)



if __name__ == '__main__':
	main(args.target,args.dns)
