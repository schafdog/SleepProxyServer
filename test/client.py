import socket
import struct
import dns.message
import dns.update
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.rdtypes.IN.A
import dns.edns
import uuid

MCAST_GRP = "10.0.0.16" # "224.0.0.251"
MCAST_PORT = 3535 # 5353

def get_mac_bytes():
    mac = uuid.getnode()  # 48-bit MAC
    return mac.to_bytes(6, "big")

def build_mdns_response():
    # Create response message
    msg = dns.update.Update("local.")
    msg.flags |= dns.flags.QR   # Response flag
    msg.flags |= dns.flags.AA   # Authoritative Answer

    # Service name (_http._tcp.local)
    service = dns.name.from_text("_http._tcp.local.")
    instance = dns.name.from_text("MyService._http._tcp.local.")
    hostname = dns.name.from_text("myhost.local.")

    # PTR: service discovery
    msg.answer.append(dns.rrset.from_text(service, 120, "IN", "PTR", str(instance)))

    # SRV: where the service lives (port 8080 at myhost.local)
    msg.additional.append(dns.rrset.from_text(instance, 120, "IN", "SRV", "0 0 8080 myhost.local."))

    # TXT: metadata
    msg.additional.append(dns.rrset.from_text(instance, 120, "IN", "TXT", "path=/"))

    # A: IPv4 address for host
    msg.additional.append(dns.rrset.from_text(hostname, 120, "IN", "A", "192.168.1.42"))

    # Add EDNS(0) OPT record
    msg.use_edns(edns=True, payload=1232)
    mac_bytes = get_mac_bytes()
    opt = dns.edns.GenericOption(dns.edns.NSID, mac_bytes)
    msg.opt.options.append(opt)

    return msg

def send_mdns_response():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    ttl = struct.pack("B", 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    msg = build_mdns_response()
    data = msg.to_wire()

    # Multicast response
    sock.sendto(data, (MCAST_GRP, MCAST_PORT))
    print("📤 Sent mDNS response with EDNS")

if __name__ == "__main__":
    send_mdns_response()
