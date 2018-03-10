# Scapy HTTP GET #
Created to better understand the TCP 3-Way-Handshake and the relationship of the Seq/Ack numbers.
Also includes a Scapy DNS Query.

Sample output:

```
user@host:# python scapy_http_get.py -d 8.8.4.4 -t icanhazip.com
!!! Requesting DNS lookup for icanhazip.com
>>> 8.8.8.8    DNS Q:    qd=icanhazip.com    qr=0    rd=1    ad=1
Begin emission:
.Finished to send 1 packets.
*
Received 2 packets, got 1 answers, remaining 0 packets
!!! Received DNS answer from DNS Servers 8.8.8.8
192.168.0.3 <<<    DNS A:    rdata=XX.XXX.XX.XXX
!!! Determined our internal IP is 192.168.0.3



!!! Sending SYN
seq = our choice
ack = 0
>>> XX.XXX.XX.XXX    S:    seq=3350301708    ack=0
Begin emission:
Finished to send 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
seq = other parties choice
ack = last-seq-num + 1
192.168.0.3 <<<    SA:    seq=1800559161    ack=3350301709

!!! Responding with ACK
seq = last-ack-num
ack = last-seq-num + 1
>>> XX.XXX.XX.XXX    A:    seq=3350301709    ack=1800559162

.
Sent 1 packets.
!!! Sending HTTP GET via PSH-ACK
seq = last_seq_num
ack = last_ack_num
>>> XX.XXX.XX.XXX    PA:    seq=3350301709    ack=1800559162    len=180
>>> PAYLOAD: GET / HTTP/1.1
	Host: icanhazip.com
	User-Agent: Python-Scapy
	Accept: */*
	Connection: keep-alive
	X-SECURITY: Hello World, this is my HTTP GET request I've crafted it myself!
	
	
Begin emission:
Finished to send 1 packets.
*****
Received 5 packets, got 5 answers, remaining 0 packets
seq = last_ack_num
ack = last_seq_num + last-pkt-len(180)
192.168.0.3 <<<    FPA:    seq=1800559162    ack=3350301889
<<< PAYLOAD: HTTP/1.1 200 OK
	Server: nginx
	Date: Sat, 03 Feb 2018 01:56:10 GMT
	Content-Type: text/plain; charset=UTF-8
	Content-Length: 12
	Connection: close
	X-SECURITY: This site DOES NOT distribute malware. Get the facts. https://goo.gl/1FhVpg
	X-RTFM: Learn about this site at http://bit.ly/icanhazip-faq and do not abuse the service.
	Access-Control-Allow-Origin: *
	Access-Control-Allow-Methods: GET
	
	YYY.YYY.YYY.YYY
	
	
!!! Closing with FIN-ACK
seq = last-ack-num
ack = last-seq-num + last-pkt-len(411) + 1
>>> XX.XXX.XX.XXX    FA:    seq=3350301889    ack=1800559574
Begin emission:
Finished to send 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
seq = last-ack-num
ack = last-seq-num + 1
192.168.0.3 <<<    A:    seq=1800559574    ack=3350301890

Finished. Exiting.
