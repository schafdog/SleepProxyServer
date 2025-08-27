import dns.message
import dns.edns
import binascii

def mac_to_eui64(mac_bytes: bytes) -> bytes:
    """
    Convert a 6-byte MAC to an 8-byte EUI-64 (RFC 4291 / RFC 6975).
    """
    if len(mac_bytes) != 6:
        raise ValueError("MAC must be 6 bytes")
    return mac_bytes[:3] + b"\xff\xfe" + mac_bytes[3:]

# Example MAC (00:11:22:33:44:55)
mac = bytes.fromhex("001122334455")
eui64 = mac_to_eui64(mac)
print("EUI-64:", binascii.hexlify(eui64))

# Build a DNS query
q = dns.message.make_query("example.com", "A")

# Attach OwnerOption (EDNS option code 4)
owner_opt = dns.edns.GenericOption(4, eui64)
# Add EDNS with the option
q.use_edns(edns=True, payload=1232, options=[owner_opt])

# Serialize to wire
wire = q.to_wire()
print("Wire bytes:", wire.hex())

# Roundtrip parse
parsed = dns.message.from_wire(wire)
print("Parsed EDNS options:", parsed.opt[0].options)

# Verify OwnerOption data
opt = parsed.opt[0].options
print("OwnerOption (hex):", binascii.hexlify(opt.data))
