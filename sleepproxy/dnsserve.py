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

# Custom EDNS options for dnslib
UL_OPTION = 2      # Update Lease option code
OWNER_OPTION = 4   # Owner option code

class UpdateLeaseOption:
    """EDNS option for Dynamic DNS Update Leases
    http://tools.ietf.org/html/draft-sekar-dns-ul-01"""
    def __init__(self, lease):
        self.otype = UL_OPTION
        self.lease = lease

    @classmethod
    def from_wire(cls, data):
        if len(data) != 4:
            raise ValueError("UpdateLeaseOption must be 4 bytes")
        (lease,) = struct.unpack("!L", data)
        return cls(lease)

    def __repr__(self):
        return "UpdateLeaseOption(lease=%d)" % self.lease

class OwnerOption:
    """EDNS option for DNS-SD Sleep Proxy Service client MAC address hinting
    http://tools.ietf.org/html/draft-cheshire-edns0-owner-option-00"""
    def __init__(self, ver=0, seq=1, pmac=None, wmac=None, passwd=None):
        self.otype = OWNER_OPTION
        self.ver = ver
        self.seq = seq
        self.pmac = self._mac2text(pmac) if pmac else None
        self.wmac = self._mac2text(wmac) if wmac else None
        self.passwd = passwd

    @staticmethod
    def _mac2text(mac):
        if not mac: return mac
        if isinstance(mac, bytes):
            mac = binascii.hexlify(mac).decode('ascii')
        elif isinstance(mac, str) and len(mac) == 6:  # Binary string
            mac = binascii.hexlify(mac.encode('latin1')).decode('ascii')
        return mac.lower().translate({ord(c): None for c in '.:-'})  # Remove delimiters

    @classmethod
    def from_wire(cls, data):
        if len(data) < 8:
            raise ValueError("OwnerOption must be at least 8 bytes")
            
        ver, seq = struct.unpack('!BB', data[0:2])
        
        if len(data) >= 8:
            pmac = data[2:8]
        if len(data) >= 14:
            wmac = data[8:14]
        else:
            wmac = pmac
        if len(data) >= 18:
            passwd = data[14:18]
        elif len(data) >= 20:
            passwd = data[14:20]
        else:
            passwd = None
            
        return cls(ver, seq, pmac, wmac, passwd)

    def __repr__(self):
        return "OwnerOption(ver=%d, seq=%d, pmac=%s, wmac=%s)" % (
            self.ver, self.seq, self.pmac, self.wmac)

def parse_edns_options(message):
    """Parse EDNS options from a dnslib DNSRecord
    Returns dict with parsed options"""
    options = {}
    
    if not hasattr(message, 'ar') or not message.ar:
        return options
        
    # Look for OPT record in additional section
    for rr in message.ar:
        if rr.rtype == QTYPE.OPT:
            # OPT record found - parse the options
            opt_data = rr.rdata.data if hasattr(rr.rdata, 'data') else bytes(rr.rdata)
            
            # Parse EDNS options from OPT rdata
            offset = 0
            while offset < len(opt_data):
                if offset + 4 > len(opt_data):
                    break
                    
                # Parse option header: code (2 bytes) + length (2 bytes)
                opt_code, opt_len = struct.unpack('!HH', opt_data[offset:offset+4])
                offset += 4
                
                if offset + opt_len > len(opt_data):
                    break
                    
                opt_payload = opt_data[offset:offset+opt_len]
                offset += opt_len
                
                # Parse known option types
                try:
                    if opt_code == UL_OPTION:
                        options['lease'] = UpdateLeaseOption.from_wire(opt_payload)
                    elif opt_code == OWNER_OPTION:
                        options['owner'] = OwnerOption.from_wire(opt_payload)
                    else:
                        logging.debug("Unknown EDNS option code: %d" % opt_code)
                except Exception as e:
                    logging.debug("Failed to parse EDNS option %d: %s" % (opt_code, e))
                    
    return options

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
            try:
                ifaddresses = netifaces.ifaddresses(iface)
                for af, addresses in ifaddresses.items():
                    if af not in (netifaces.AF_INET, netifaces.AF_INET6): continue
                    for address in addresses:
                        try:
                            mask = address['netmask']
                            if af == netifaces.AF_INET6: mask = (mask.count('f') * 4) # convert linux masks to prefix length...gooney
                            if address['addr'].find('%') > -1: continue #more linux ipv6 stupidity
                            iface_net = ipaddress.ip_interface('%s/%s' % (address['addr'], mask)).network
                            if ipaddress.ip_address(addr[0]) in iface_net:
                                # Try to get MAC address - different systems use different constants
                                mac_addr = None
                                for link_af in [netifaces.AF_LINK, 17, 18]:  # Try common AF_LINK values
                                    try:
                                        if link_af in ifaddresses and ifaddresses[link_af]:
                                            mac_addr = ifaddresses[link_af][0]['addr']
                                            break
                                    except (KeyError, IndexError):
                                        continue
                                
                                if mac_addr:
                                    info['mymac'] = mac_addr
                                    info['myif'] = iface
                                else:
                                    logging.debug("Could not find MAC address for interface %s" % iface)
                                    info['myif'] = iface
                                break
                        except Exception as e:
                            logging.debug("Error processing address %s on interface %s: %s" % (address.get('addr', 'unknown'), iface, e))
                            continue
            except Exception as e:
                logging.debug("Error processing interface %s: %s" % (iface, e))
                continue
    
        for rr in message.auth:
            # dnslib doesn't have the cache-flush bit handling like dnspython
            # The bit is embedded in the rclass field, remove it if present
            if rr.rclass & 0x8000:  # Cache-flush bit
                rr.rclass &= ~0x8000  # Remove cache-flush bit
            
            info['records'].append(rr)
            self._add_addresses(info, rr)
    
        logging.debug('NSUPDATE START--\n\n%s\n\n--NSUPDATE END' % message)
 
        # Parse EDNS options using our custom parser
        edns_options = parse_edns_options(message)
        logging.debug("Parsed EDNS options: %s" % edns_options)
        
        # Extract information from EDNS options
        if 'lease' in edns_options:
            info['ttl'] = edns_options['lease'].lease
            logging.debug("Found lease option: %d seconds" % info['ttl'])
            
        if 'owner' in edns_options:
            owner_opt = edns_options['owner']
            info['othermac'] = owner_opt.pmac  # Primary MAC (WOL target)
            logging.debug("Found owner option: MAC=%s, ver=%d, seq=%d" % (
                owner_opt.pmac, owner_opt.ver, owner_opt.seq))
        else:
            # Fallback: Extract othermac from hostname or use a default
            # This maintains compatibility when EDNS options aren't available
            othermac = None
            for rr in info.get('records', []):
                rr_name = str(rr.rname).lower()
                # Look for patterns like "d49a20de9d39.local" (MAC in hostname)
                if '.local' in rr_name and len(rr_name.split('.')[0]) == 12:
                    potential_mac = rr_name.split('.')[0]
                    if all(c in '0123456789abcdef' for c in potential_mac):
                        othermac = potential_mac
                        break
            
            if not othermac:
                # Generate a MAC-like identifier from the source IP
                ip_parts = addr[0].split('.')
                if len(ip_parts) == 4:
                    othermac = "ff%02x%02x%02x%02x00" % (int(ip_parts[0]), int(ip_parts[1]), int(ip_parts[2]), int(ip_parts[3]))
                else:
                    othermac = "ffffffffffff"  # Default fallback
                    
            info['othermac'] = othermac
            logging.warning("No EDNS OwnerOption found, using fallback othermac: %s" % othermac)

        self._answer(addr, message)

        # Call manage_host if we have both required EDNS options (or fallback data)
        if 'lease' in edns_options and 'owner' in edns_options:
            # Have both proper EDNS options - this is a full registration
            logging.info("Processing full SPS registration with EDNS options")
            manage_host(info)
        elif 'othermac' in info:
            # Have fallback MAC address - proceed anyway for testing
            logging.warning("Processing SPS registration with fallback data")
            manage_host(info)
        else:
            # Just a post-wake notification (incremented seq number without both options)
            logging.debug("Skipping registration - appears to be post-wake notification")
        
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
