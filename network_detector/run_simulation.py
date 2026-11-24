"""Run synthetic packet simulations against detector.packet_callback()
This script crafts packets and calls the detector's packet handler directly (no network send).
"""
from scapy.all import Ether, ARP, BOOTP, DHCP, IP, UDP, DNS, DNSRR, DNSQR
import detector
import config
import time

# Ensure we don't perform active probing or blocking during simulation
config.ACTIVE_PROBING_ENABLED = False
config.MITIGATION_MODE = 'log'
config.AUTO_BLOCK_ENABLED = False

# Clear state
with detector.state_lock:
    detector.state['alerts'].clear()
    detector.state['arp_table'].clear()

print("Starting simulation tests...")

# 1) GARP impersonation: claim gateway IP from different MAC
config.GATEWAY_IP = config.GATEWAY_IP  # use existing
config.GATEWAY_MAC = 'aa:bb:cc:dd:ee:ff'  # pinned correct gw

garp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=config.GATEWAY_IP, hwsrc="aa:bb:cc:dd:ee:00", pdst=config.GATEWAY_IP, hwdst="ff:ff:ff:ff:ff:ff")
print("Simulating GARP impersonation...")
detector.packet_callback(garp)

# 2) ARP flip-flop for a client IP
arp_reply1 = Ether()/ARP(op=2, psrc="192.168.1.50", hwsrc="00:11:22:33:44:55", pdst="192.168.1.50", hwdst="ff:ff:ff:ff:ff:ff")
arp_reply2 = Ether()/ARP(op=2, psrc="192.168.1.50", hwsrc="66:77:88:99:aa:bb", pdst="192.168.1.50", hwdst="ff:ff:ff:ff:ff:ff")
print("Simulating ARP flip-flop (two different MAC replies)...")
detector.packet_callback(arp_reply1)
# small gap
time.sleep(0.5)
detector.packet_callback(arp_reply2)
# repeat to trigger flip-flop detection
time.sleep(0.5)
detector.packet_callback(arp_reply1)

# 3) DHCPACK learning a binding
dhcp_ack = Ether(src="de:ad:be:ef:00:01", dst="00:11:22:33:44:66")/BOOTP(op=2, yiaddr="192.168.1.100")/DHCP(options=[('message-type', 5), 'end'])
print("Simulating DHCPACK learning binding 192.168.1.100 -> 00:11:22:33:44:66...")
detector.packet_callback(dhcp_ack)

# 4) DNS response from untrusted server (simulate spoof)
dns_resp = Ether()/IP(src="1.2.3.4", dst="192.168.1.10")/UDP(sport=53, dport=33333)/DNS(id=0x1234, qr=1, qd=DNSQR(qname="example.test"), an=DNSRR(rrname="example.test", rdata="5.6.7.8"))
print("Simulating DNS response from untrusted server 1.2.3.4...")
detector.packet_callback(dns_resp)

# Print alerts summary
print("\nAlerts generated:")
with detector.state_lock:
    for a in detector.state['alerts']:
        print(f"- [{a['time']}] {a['type']} Risk={a['risk']} {a['message']}")

print('\nSimulation complete.')
