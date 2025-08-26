import logging
import dbus
import dns.rdatatype
import dns.rdataclass

# http://git.0pointer.net/avahi.git/tree/avahi-python/avahi/__init__.py
IF_UNSPEC = -1
PROTO_UNSPEC = -1 #dual-stack
PROTO_INET = 0 #v4
PROTO_INET6 = 1

# Cache-flush bit in mDNS RFC6762 ch#10.2 
# http://www.opensource.apple.com/source/mDNSResponder/mDNSResponder-522.1.11/mDNSCore/DNSCommon.c
# kDNSClass_UniqueRRSet - have to filter it out from some OSX SPS clients' rdatas
# dnslib handles this as bit 0x8000 in the rclass field 

_HOSTS = {}

def string_to_byte_array(s):
    r = []
    for c in s:
        r.append(dbus.Byte(ord(c)))
    return r

def string_array_to_txt_array(t):
    l = []
    for s in t:
        l.append(string_to_byte_array(s))
    return l

def register_service(record):
    group = _get_group()

    #http://linux.die.net/man/5/avahi.service
    group.AddService(
        record.get('iface', IF_UNSPEC),
        record.get('protocol', PROTO_UNSPEC),
        dbus.UInt32(record.get('flags', 0)),
        record.get('name'),
        record.get('stype'),
        record.get('domain'),
        record.get('host'),
        dbus.UInt16(record.get('port')),
        string_array_to_txt_array(record.get('text', '')),
    )

    group.Commit()

def handle(mac, records):
    if mac in _HOSTS:
        logging.debug("I already seem to be handling mDNS for %s" % (mac, ))
        return
    logging.info('Now mirroring mDNS advertisements from %s to local Avahi server' % (mac))
    group = _get_group()
    _HOSTS[mac] = group
    _update_to_group(group, records)
    result = group.Commit(utf8_strings=True)
    logging.debug("Result of Commit() on mDNS records was %s" % (result, ))

def forget(mac):
    logging.info("Removing %s from mDNS handler & Avahi" % (mac, ))
    if mac not in _HOSTS:
        logging.debug("I don't seem to be managing mDNS for %s" % (mac, ))
        return
    group = _HOSTS.pop(mac)
    group.Free()

def _update_to_group(group, records):
    """Convert dnslib RR records to additions to an Avahi mDNS group"""
    from dnslib import QTYPE, CLASS
    
    for record in records:
        # Remove cache-flush bit from dnslib RR
        record.rclass &= ~0x8000
        
        # Check if it's a valid record type
        if record.rtype not in [QTYPE.PTR, QTYPE.A, QTYPE.AAAA, QTYPE.TXT, QTYPE.SRV]:
            logging.warning('Invalid DNS RR type (%s), not adding mDNS record to Avahi' % record.rtype)
            continue

        if record.rclass != CLASS.IN:
            logging.warning('Invalid DNS RR class (%s), not adding mDNS record to Avahi' % record.rclass)
            continue

        #if (record.rtype == QTYPE.PTR and ':' in record_data) or record.rtype == QTYPE.AAAA:
        #    continue #ignore IPV6 for now, can't sniff those connections

        try:
            # Convert dnslib RR to Avahi format  
            rname = str(record.rname)
            
            # Get binary rdata from dnslib record
            import io
            buffer = io.BytesIO()
            record.rdata.pack(buffer)
            rdata_bytes = buffer.getvalue()
            
            group.AddRecord(
              IF_UNSPEC,  # iface
              PROTO_UNSPEC,  # proto _INET & _INET6
              dbus.UInt32(256),  # AvahiPublishFlags (use multicast)
              rname, #name
              dbus.UInt16(record.rclass), #class
              dbus.UInt16(record.rtype), #type
              dbus.UInt32(record.ttl), #ttl
              [dbus.Byte(b) for b in rdata_bytes] #rdata as byte array
            )
            logging.info('added mDNS record to Avahi: %s' % record)
        except UnicodeDecodeError:
            logging.warning('malformed unicode in rdata, skipping: %s' % record)
        except dbus.exceptions.DBusException as e:
            if e.get_dbus_name() == 'org.freedesktop.Avahi.InvalidDomainNameError':
                logging.warning('not mirroring mDNS record with special chars: %s' % record)
                continue # skip this record since Avahi will reject it
                # mac probably sent a device_info PTR with spaces and parentheses in the friendly description
                #  per https://tools.ietf.org/html/rfc6763#section-4.1.3
                # fanboy\032\(2\)._eppc._tcp.local. 4500 CLASS32769 TXT "" # `fanboy (2)`
                # mDNS.c sends UTF8, dnslib handles this better than dnspython
                # Avahi only takes [a-zA-Z0-9.-] in domain names
            else:
                logging.warning('Error with mDNS record: %s' % record)
                raise


def _get_group():
    """Create a group, on the system bus"""
    bus = dbus.SystemBus()
    server = dbus.Interface(
        bus.get_object('org.freedesktop.Avahi', '/'),
        'org.freedesktop.Avahi.Server',
    )

    return dbus.Interface(
        bus.get_object('org.freedesktop.Avahi', server.EntryGroupNew()),
        'org.freedesktop.Avahi.EntryGroup',
    )
