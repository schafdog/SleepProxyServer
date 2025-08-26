"""A NSUPDATE server class for asyncio, emulating apple's mDNSResponder SPS server"""
# Copyright (c) 2013 Russell Cloran
# Copyright (c) 2014 Joey Korkames
# Copyright (c) 2025 Dennis Schafroth

import traceback
import struct
import logging

import dns.name
import dns.flags
import dns.message
import dns.reversename
import dns.edns
import dns.wire

import ipaddress
import netifaces
import binascii
import asyncio


# https://github.com/aosm/mDNSResponder/commits/master
# http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/mDNS.c
# [SLEEPER]BeginSleepProcessing(),NetWakeResolve(),SendSPSRegistration() -> [SPS]mDNSCoreReceiveUpdate() -> [SLEEPER]mDNSCoreReceive(),mDNSCoreReceiveUpdateR()
# [WAKER]*L3 -> [SPS]*BPF,SendResponses(),SendWakeup(),WakeOnResolve++,mDNSSendWakeOnResolve() -> [SLEEPER]

# http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
dns.edns.UL = 2
dns.edns.OWNER = 4

class UpdateLeaseOption(dns.edns.Option):
    """EDNS option for Dynamic DNS Update Leases
http://tools.ietf.org/html/draft-sekar-dns-ul-01"""
    def __init__(self, lease):
        super(UpdateLeaseOption, self).__init__(dns.edns.UL)
        self.lease = lease

    def to_wire(self, file):
        data = struct.pack("!L", self.lease)
        file.write(data)

    @classmethod
    def from_wire(cls, otype, wire, current, olen):
        data = wire[current:current + olen]
        (lease,) = struct.unpack("!L", data)
        return cls(lease)

    def __repr__(self):
        return "%s[OPT#%s](%s)" % (
            self.__class__.__name__,
            self.otype,
            self.lease
        )

dns.edns._type_to_class.update({dns.edns.UL: UpdateLeaseOption})

#SetupOwnerOpt() mDNS.c
class OwnerOption(dns.edns.Option):
    """EDNS option for DNS-SD Sleep Proxy Service client mac address hinting
http://tools.ietf.org/html/draft-cheshire-edns0-owner-option-00"""
    def __init__(self, ver=0, seq=1, pmac=None, wmac=None, passwd=None):
        super(OwnerOption, self).__init__(dns.edns.OWNER)
        self.ver = ver
        self.seq = seq
        self.pmac = self._mac2text(pmac)
        self.wmac = self._mac2text(wmac)
        self.passwd = passwd

    @staticmethod
    def _mac2text(mac):
        if not mac: return mac
        #if len(mac) == 6: mac.encode('hex') #this was a wire-format binary
        mac = binascii.hexlify(mac).decode('ascii')
        return mac.lower().translate({ord(c): None for c in '.:-'}) #del common octet delimiters

    def to_wire(self, file):
        data = bytes([self.ver, self.seq])
        #data += self.pmac.decode('hex')
        data += binascii.unhexlify(self.pmac)
        if self.pmac != self.wmac:
           data += binascii.unhexlify(self.wmac)
           if self.passwd: data += self.passwd

        file.write(data)

    @classmethod
    def from_wire(cls, otype, wire, current, olen):
        data = wire[current:current + olen]
        if olen == 20:
           (ver, seq, pmac, wmac, passwd) = struct.unpack('!BB6s6s6s',data)
           return cls(ver, seq, pmac, wmac, passwd)
        elif olen == 18:
           (ver, seq, pmac, wmac, passwd) = struct.unpack('!BB6s6s4s',data)
           return cls(ver, seq, pmac, wmac, passwd)
        elif olen == 14:
           (ver, seq, pmac, wmac) = struct.unpack("!BB6s6s",data)
           return cls(ver, seq, pmac, wmac)
        elif olen == 8:
           (ver, seq, pmac) = struct.unpack("!BB6s",data)
           return cls(ver, seq, pmac)

    def __repr__(self):
        return "%s[OPT#%s](%s, %s, %s, %s, %s)" % (
            self.__class__.__name__,
            self.otype,
            self.ver,
            self.seq,
            self.pmac,
            self.wmac,
            self.passwd
        )

dns.edns._type_to_class.update({dns.edns.OWNER: OwnerOption})

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
            # Try scapy parsing first - it's more robust with custom options
            from scapy.layers.dns import DNS
            try:
                logging.debug("Trying scapy DNS parsing from %s" % addr[0])
                scapy_dns = DNS(data)
                logging.debug("Scapy DNS parsing successful from %s, converting to dnspython format" % addr[0])
                # For now, fallback to dnspython but log scapy success
                message = dns.message.from_wire(data, ignore_trailing=True)
            except Exception as scapy_error:
                logging.debug("Scapy parsing failed (%s), trying dnspython from %s" % (scapy_error, addr[0]))
                message = dns.message.from_wire(data, ignore_trailing=True)
        except dns.message.BadEDNS: 
            #yosemite's discoveryd sends an OPT record per active NIC, dnspython doesn't like more than 1 OPT record
            #  https://github.com/rthalley/dnspython/blob/master/dns/message.py#L642 
            #  so turn off Wi-Fi for ethernet-connected clients
            return #or send back an nxdomain or servfail
        except (NotImplementedError, dns.exception.FormError, ValueError) as e:
            logging.warning("DNS message from %s parsing failed (%s), trying fallback methods" % (addr[0], type(e).__name__))
            logging.debug("Error details: %s" % str(e))
            
            # Try multiple fallback parsing strategies
            message = None
            for strategy in ['ignore_edns', 'ignore_additional', 'basic_only']:
                try:
                    if strategy == 'ignore_edns':
                        # Try without EDNS processing
                        message = dns.message.from_wire(data, ignore_trailing=True, one_rr_per_rrset=True, keyring=None, ignore_errors=True)
                    elif strategy == 'ignore_additional':
                        # Try parsing but skip additional section entirely
                        wire_data = dns.wire.Message(data)
                        message = dns.message.Message()
                        message.id = wire_data.id()
                        message.flags = wire_data.flags()
                        # Only parse question and authority sections, skip additional
                        for section in [dns.message.MessageSection.QUESTION, dns.message.MessageSection.AUTHORITY]:
                            try:
                                section_count = wire_data.count(section)
                                for _ in range(section_count):
                                    rr = wire_data.read_rr(section)
                                    message.find_rrset(rr.name, rr.rdclass, rr.rdtype, create=True).add(rr)
                            except:
                                continue
                        break
                    else:  # basic_only
                        # Last resort: create minimal message structure
                        message = dns.message.Message()
                        message.id = int.from_bytes(data[0:2], 'big')
                        message.flags = int.from_bytes(data[2:4], 'big')
                        logging.warning("Using minimal DNS message parsing for %s" % addr[0])
                        break
                        
                    if message:
                        logging.info("Successfully parsed DNS message from %s using %s strategy" % (addr[0], strategy))
                        break
                except Exception as fallback_error:
                    logging.debug("Fallback strategy %s failed: %s" % (strategy, fallback_error))
                    continue
            
            if not message:
                logging.error("All DNS parsing strategies failed for message from %s" % addr[0])
                return
        except: #no way to just catch dns.exceptions.*
            logging.warning("Error decoding DNS message from %s" % addr[0])
            logging.debug(traceback.format_exc())
            return
    
        if message.edns < 0:
            logging.warning("Received non-EDNS message from %s, ignoring" % addr[0])
            return
    
        if not (message.opcode() == 5 and message.authority):
            logging.warning("Received non-UPDATE message from %s, ignoring" % addr[0])
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
    
        for rrset in message.authority:
            rrset.rdclass %= dns.rdataclass.UNIQUE #remove cache-flush bit
            #rrset.rdata = rrset.rdata.decode(utf-8)
            info['records'].append(rrset)
            self._add_addresses(info, rrset)
    
        logging.debug('NSUPDATE START--\n\n%s\n\n%s\n\n--NSUPDATE END' % (message,message.options))
 
        for option in message.options:
            if option.otype == dns.edns.UL:
                info['ttl'] = option.lease #send-WOL-no-later-than timer TTL
            if option.otype == dns.edns.OWNER:
                info['othermac'] = option.pmac #WOL target mac
                #if option.passwd: # password required in wakeup packet
                #  mDNS.c:SendSPSRegistrationForOwner() doesn't seem to add a password
    
        self._answer(addr, message)

        if len(message.options) == 2:
           # need both an owner and an update-lease option, else its just a post-wake notification (incremented seq number)
           manage_host(info)
        
    def _add_addresses(self, info, rrset):
        if rrset.rdtype != dns.rdatatype.PTR: return
        if rrset.rdclass != dns.rdataclass.IN: return
    
        #if not rrset.name.to_text().endswith('.in-addr.arpa.'): return #TODO: support SYN sniffing for .ip6.arpa. hosts
        if not rrset.name.to_text().endswith('.arpa.'): return #all we care about are reverse-dns records
    
        info['addresses'].append(dns.reversename.to_address(rrset.name))
    
    def _answer(self, address, query):
        response = dns.message.make_response(query)
        response.flags = dns.flags.QR | dns.opcode.to_flags(dns.opcode.UPDATE)
        #needs a single OPT record to confirm registration:  0 TTL    4500   48 . OPT Max 1440 Lease 7200 Vers 0 Seq  21 MAC D4:9A:20:DE:9D:38
        response.use_edns(edns=True, ednsflags=dns.rcode.NOERROR, payload=query.payload, options=[query.options[0]]) #payload should be 1440, theoretical udp-over-eth maxsz stdframe
        logging.warning("Confirming SPS registration @%s with %s[%s] for %s secs" % (query.options[1].seq, address[0], query.options[1].pmac, query.options[0].lease))
        logging.debug('RESPONSE--\n\n%s\n\n%s\n\n--RESPONSE END' % (response,response.options))
        self.transport.sendto(response.to_wire(), address)
