"""A NSUPDATE server class for asyncio, emulating apple's mDNSResponder SPS server"""
# Copyright (c) 2013 Russell Cloran
# Copyright (c) 2014 Joey Korkames
# Copyright (c) 2025 Dennis Schafroth

import traceback
import struct
import logging

from dnslib import DNSRecord, DNSHeader, RR, QTYPE, CLASS
import dnslib.dns

import ipaddress
import netifaces
import binascii
import asyncio


# https://github.com/aosm/mDNSResponder/commits/master
# http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/mDNS.c
# [SLEEPER]BeginSleepProcessing(),NetWakeResolve(),SendSPSRegistration() -> [SPS]mDNSCoreReceiveUpdate() -> [SLEEPER]mDNSCoreReceive(),mDNSCoreReceiveUpdateR()
# [WAKER]*L3 -> [SPS]*BPF,SendResponses(),SendWakeup(),WakeOnResolve++,mDNSSendWakeOnResolve() -> [SLEEPER]

# http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
# TODO: Implement custom EDNS options for dnslib
# UL = 2  # Update Lease option
# OWNER = 4  # Owner option

# TODO: Custom EDNS options for dnslib
# The following UpdateLeaseOption and OwnerOption classes were specific to dnspython
# They need to be reimplemented for dnslib's EDNS handling system
#
# UpdateLeaseOption: EDNS option for Dynamic DNS Update Leases (option code 2)
# OwnerOption: EDNS option for Sleep Proxy Service MAC address hinting (option code 4)
#
# For now, basic DNS UPDATE parsing works without these custom options
# The Sleep Proxy Server will still function but won't parse the custom EDNS data

from sleepproxy.manager import manage_host

__all__ = ['SleepProxyServer']

class SleepProxyServer(asyncio.DatagramProtocol):
    def __init__(self, address):
        self.address = address
        self.transport = None
        
    def connection_made(self, transport):
        self.transport = transport
        
    async def serve_forever(self):
        loop = asyncio.get_running_loop()
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: self,
                local_addr=self.address
            )
            logging.info("Successfully bound to %s:%d" % self.address)
        except Exception as e:
            logging.error("Failed to bind to %s:%d - %s" % (self.address[0], self.address[1], e))
            raise
            
        try:
            await asyncio.Future()  # Run forever
        finally:
            transport.close()

    # #@classmethod
    # #def get_listener(self, address, family=None):
    # #    #return _udp_socket(address, reuse_addr=self.reuse_addr, family=family)
    # #    sock = socket.socket(family=family, type=socket.SOCK_DGRAM)
    # #    #if family == socket.AF_INET6: logging.warning("dual-stacking!"); sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
    # #    if family == socket.AF_INET6: logging.warning("disabling dual-stacking!"); sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)
    # #    sock.bind(address)
    # #    return sock

    def datagram_received(self, data, addr):
        try:
            # Use dnslib for more robust DNS parsing
            logging.debug("Parsing DNS message from %s with dnslib" % addr[0])
            message = DNSRecord.parse(data)
            logging.debug("Successfully parsed DNS message from %s" % addr[0])
        except Exception as e:
            logging.warning("Failed to parse DNS message from %s: %s" % (addr[0], e))
            logging.debug("Raw data (hex): %s" % data[:64].hex())
            return
    
        # Check if it's a DNS UPDATE message (opcode 5)
        if message.header.opcode != 5:
            logging.warning("Received non-UPDATE message from %s, ignoring (opcode=%d)" % (addr[0], message.header.opcode))
            return
        
        if not message.auth:
            logging.warning("Received UPDATE message without authority section from %s, ignoring" % addr[0])
            return
    
        logging.debug("Received SPS registration from %s, parsing" % addr[0])

        info = {'records': [], 'addresses': []}
    
        # Try to guess the interface this came in on
        #   todo - precompute this table on new()?
        for iface in netifaces.interfaces():
            ifaddresses = netifaces.ifaddresses(iface)
            for af, addresses in ifaddresses.items():
                if af not in (netifaces.AF_INET, netifaces.AF_INET6): continue
                for address in addresses:
                    mask = address['netmask']
                    if af == netifaces.AF_INET6: mask = (mask.count('f') * 4) # convert linux masks to prefix length...gooney
                    if address['addr'].find('%') > -1: continue #more linux ipv6 stupidity
                    iface_net = ipaddress.ip_interface('%s/%s' % (address['addr'], mask)).network
                    if ipaddress.ip_address(addr[0]) in iface_net:
                        info['mymac'] = ifaddresses[netifaces.AF_LINK][0]['addr']
                        info['myif'] = iface
    
        for rr in message.auth:
            # dnslib doesn't have the cache-flush bit handling like dnspython
            # The bit is embedded in the rclass field, remove it if present
            if rr.rclass & 0x8000:  # Cache-flush bit
                rr.rclass &= ~0x8000  # Remove cache-flush bit
            
            info['records'].append(rr)
            self._add_addresses(info, rr)
    
        logging.debug('NSUPDATE START--\n\n%s\n\n--NSUPDATE END' % message)
 
        # Process EDNS options - dnslib handles EDNS differently
        # For now, we'll extract basic info and handle custom options later
        if hasattr(message, 'edns') and message.edns:
            logging.debug("EDNS options found in message")
            # TODO: Handle custom EDNS options (UpdateLeaseOption, OwnerOption)
            # This would require custom EDNS option parsing in dnslib
    
        self._answer(addr, message)

        # For now, always call manage_host - EDNS option handling to be implemented
        manage_host(info)
        
    def _add_addresses(self, info, rr):
        if rr.rtype != QTYPE.PTR: return
        if rr.rclass != CLASS.IN: return
    
        # Check if it's a reverse DNS record (.arpa.)
        rr_name = str(rr.rname)
        if not rr_name.endswith('.arpa.'): return
    
        # Convert reverse DNS name to IP address
        try:
            if rr_name.endswith('.in-addr.arpa.'):
                # IPv4 reverse DNS
                parts = rr_name.replace('.in-addr.arpa.', '').split('.')
                ip = '.'.join(reversed(parts))
                info['addresses'].append(ip)
            elif rr_name.endswith('.ip6.arpa.'):
                # IPv6 reverse DNS - more complex, for now skip
                logging.debug("IPv6 reverse DNS not yet implemented for dnslib: %s" % rr_name)
        except Exception as e:
            logging.debug("Failed to parse reverse DNS %s: %s" % (rr_name, e))
    
    def _answer(self, address, query):
        # Create DNS UPDATE response using dnslib
        response = DNSRecord(
            DNSHeader(
                id=query.header.id,
                qr=1,  # Response
                opcode=5,  # UPDATE
                rcode=0,  # NOERROR
                aa=1,  # Authoritative
            )
        )
        
        logging.warning("Confirming SPS registration from %s" % address[0])
        logging.debug('RESPONSE--\n\n%s\n\n--RESPONSE END' % response)
        
        # Send the response
        response_data = response.pack()
        self.transport.sendto(response_data, address)
