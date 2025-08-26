import logging
from scapy.all import sendp,  Ether, IP, UDP, Raw

def wake(mac):
    logging.warning("Sending WOL packet to %s" % (mac, ))
    mac_bytes = bytes.fromhex(mac)
    sendp(Ether(dst='ff:ff:ff:ff:ff:ff') / IP(dst='255.255.255.255', flags="DF") / UDP(dport=9, sport=39227) / Raw(b'\xff' * 6 + mac_bytes * 16))

if __name__ == '__main__':
    import sys
    wake(sys.argv[1])
