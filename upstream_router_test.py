#!/usr/bin/python

"""
Upstream router test by Stephen Genusa - January 2018

Determine router IP addresses for a given number of upstream hops, then ping
them for 5 seconds, take a 5 second break and repeat, reporting
results as process runs. Written to document a failing router for ISP.

Code to get router list adapted from https://github.com/leonidg/Poor-Man-s-traceroute by Leonid Grinberg
MultiPing 


Copyright 2018 by Stephen Genusa

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

from collections import defaultdict
#import optparse
import socket
import sys
import time

from multiping import MultiPing


icmp = socket.getprotobyname('icmp')
udp = socket.getprotobyname('udp')

def create_sockets(ttl):
    """
    Sets up sockets necessary for the traceroute.  We need a receiving
    socket and a sending socket.
    """
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)    
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    return recv_socket, send_socket


def get_router_ips(dest_name, port, max_hops):
    dest_addr = socket.gethostbyname(dest_name)
    ttl = 1
    router_ips = []
    while True:
        recv_socket, send_socket = create_sockets(ttl)
        recv_socket.bind(("", port))
        recv_socket.settimeout(30)
        send_socket.sendto("", (dest_name, port))
        curr_addr = None
        curr_name = None
        try:
            _, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]  # address is given as tuple
            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr
        except socket.error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
            if curr_addr not in router_ips:
                router_ips.append(curr_addr)
        else:
            curr_host = "*"
        print "%d\t%s" % (ttl, curr_host)

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break
    # Remove any bogus IPs the ISP might return        
    if "8.8.8.8" in router_ips:
        router_ips.remove("8.8.8.8")
    return router_ips


def main():
    response_count = defaultdict(int)
    noresponse_count = defaultdict(int)
    
    # Get the first 5 upstream routers to microsoft.com
    router_ips = get_router_ips("www.microsoft.com", 33434, 5)

    # Or predefine them here if traffic is so problematic that you can't rely on the get_router_ips function
    # router_ips = ["192.168.0.1", "129.41.24.31", "129.43.12.90","129.43.13.90", "22.11.112.34"]

    while True:
        for short_seq in range(1, 6):
            mp = MultiPing(router_ips)
            mp.send()
            responses, no_responses = mp.receive(4)

            for response in responses:
                response_count[response] += 1
            for noresponse in no_responses:
                noresponse_count[noresponse] += 1
            time.sleep(1)
        time.sleep(5)
        print("")
        for index, router_ip in enumerate(router_ips):
            print index + 1, "  ", router_ip, "\tresponses:", response_count[router_ip], "\tno responses:", noresponse_count[router_ip]


if __name__ == "__main__":
    main()
