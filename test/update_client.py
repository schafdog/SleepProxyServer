import socket
import struct
import dns.message
import dns.name
import dns.update
import dns.edns
import uuid
import codecs

MCAST_GRP = "10.0.0.16" #"224.0.0.251"
MCAST_PORT = 3535

def mac_to_eui64(mac_int):
    # Convert integer MAC to 6 bytes
    mac_bytes = mac_int.to_bytes(6, "big")
    # Split into two halves
    first3 = mac_bytes[:3]
    last3 = mac_bytes[3:]
    # Insert FF:FE in the middle
    eui64 = first3 + b'\xff\xfe' + last3
    # Flip U/L bit (optional, standard for EUI-64)
    eui64 = bytes([eui64[0] ^ 0x02]) + eui64[1:]
    return eui64

def get_mac_bytes():
    return mac_to_eui64(uuid.getnode())  # 48-bit MAC

def build_update_with_edns():
    # Create a DNS UPDATE message (RFC 2136)
    update = dns.update.Update("local.")
    
    # Add a fake A record for demonstration
    update.add("myhost.local.", 120, "A", "192.168.1.42")
    
    # Add EDNS(2) with UL and EDNS(4) OPT record with MAC address option
    # http://files.dns-sd.org/draft-sekar-dns-ul.txt                                                            
    # 2: Lease Time in seconds                                                                                  
    lease_time_option = dns.edns.GenericOption(
        2, struct.pack("!L", 7200)
    )

    mac_bytes = get_mac_bytes()
    # http://tools.ietf.org/id/draft-cheshire-edns0-owner-option-00.txt                                         
    # 4: edns owner option (MAC addr for WOL Magic packet)                                                      
    clean_hardware_address = "01:23:45:67:89:01".replace(":", "")
    owner_option = dns.edns.GenericOption(
        4, codecs.decode("0000" + clean_hardware_address, "hex_codec")
    )

    owner_opt = dns.edns.GenericOption(4, mac_bytes)
    # Replace default OPT with a new one containing options
    update.use_edns(edns=True, ednsflags=7200, payload=4096, options=[lease_time_option, owner_option])
    wire = update.to_wire()
    parsed = dns.message.from_wire(wire)
    print("Parsed EDNS options:", parsed)
    return update

def send_update():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

    msg = build_update_with_edns()
    data = msg.to_wire()

    sock.sendto(data, (MCAST_GRP, MCAST_PORT))
    print(f"📤 Sent UPDATE with EDNS (MAC={get_mac_bytes().hex(':')})")

if __name__ == "__main__":
    send_update()
