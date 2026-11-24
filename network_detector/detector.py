import threading
import time
import logging
import platform
import subprocess
import sqlite3
from collections import defaultdict
from scapy.all import sniff, ARP, DHCP, BOOTP, DNS, DNSRR, IP, TCP, UDP, ICMP, wrpcap, get_if_hwaddr, get_if_addr
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np

import config

# Global state for dashboard
state = {
    "alerts": [],  # List of alert dicts: {'time': str, 'type': str, 'message': str, 'risk': int}
    "counters": {
        "arp_attacks": 0,
        "dhcp_attacks": 0,
        "dns_attacks": 0,
        "ml_anomalies": 0,
        "port_scans": 0,
        "packets_processed": 0,
        "dns_packets": 0,
        "arp_packets": 0,
        "icmp_packets": 0,
        "udp_packets": 0
    },
    "blocked_macs": set(),
    "arp_table": {},  # IP -> MAC
    "sensor": {
        "interface": "Default",
        "capture_active": False,
        "promiscuous_mode": True,
        "environment": "Unknown"
    },
    "recent_dns": [],
    "ml_status": "Starting..."
}

state_lock = threading.Lock()

# --- Global Interface IP/MAC ---
our_ip = None
our_mac = None

# --- Global Initialization & Timers ---
start_time = time.time()
arp_history = defaultdict(list)  # IP -> list of (mac, timestamp) for rapid flip-flop detection
garp_flood_tracker = defaultdict(list)  # MAC -> list of GARP timestamps for flood detection
known_network_macs = set()  # Set of MACs legitimately observed on the network
our_mac = None
our_ip = None

# --- Persistent Database Setup ---
def init_db():
    try:
        conn = sqlite3.connect("network_detector.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS arp_mappings (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                last_seen REAL
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Failed to initialize SQLite database: {e}")

def db_get_mac(ip):
    try:
        conn = sqlite3.connect("network_detector.db")
        cursor = conn.cursor()
        cursor.execute("SELECT mac FROM arp_mappings WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        logging.error(f"Database error reading MAC for IP {ip}: {e}")
        return None

def db_set_mac(ip, mac):
    try:
        conn = sqlite3.connect("network_detector.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO arp_mappings (ip, mac, last_seen)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, last_seen=excluded.last_seen
        """, (ip, mac.lower(), time.time()))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Database error writing MAC for IP {ip}: {e}")

# --- ML Time-Windowed State ---
ml_window_lock = threading.Lock()
current_window = {
    "packets": 0,
    "dns_queries": 0,
    "ips": set()
}

def add_alert(attack_type, message, risk, src_mac=None, packet=None,
              attacker_ip=None, victim_ip=None, victim_mac=None, protocol=None):
    # Auto-extract fields from packet if not provided
    if packet:
        if not attacker_ip and packet.haslayer(IP):
            attacker_ip = packet[IP].src
        if not victim_ip and packet.haslayer(IP):
            victim_ip = packet[IP].dst
        if not src_mac:
            try:
                from scapy.layers.l2 import Ether
                if packet.haslayer(Ether): src_mac = packet[Ether].src
            except: pass
        if not victim_mac:
            try:
                from scapy.layers.l2 import Ether
                if packet.haslayer(Ether): victim_mac = packet[Ether].dst
            except: pass
        if not protocol:
            if packet.haslayer(TCP): protocol = "TCP"
            elif packet.haslayer(UDP): protocol = "UDP"
            elif packet.haslayer(ARP): protocol = "ARP"
            elif packet.haslayer(ICMP): protocol = "ICMP"
            else: protocol = "Other"

    agg_key = f"{attack_type}:{attacker_ip or src_mac or 'unknown'}"

    now = time.time()
    now_str = time.strftime("%H:%M:%S")

    alert_entry = {
        "time": now_str,
        "type": attack_type,
        "message": message,
        "risk": risk,
        "attacker_ip": attacker_ip or "N/A",
        "victim_ip": victim_ip or "N/A",
        "attacker_mac": src_mac or "N/A",
        "victim_mac": victim_mac or "N/A",
        "protocol": protocol or attack_type,
        "pkt_len": len(packet) if packet else 0,
        "pkt_count": 1,
        "agg_key": agg_key,
        "status": "ACTIVE",
        "first_seen": now_str,
        "last_seen": now_str,
        "first_seen_ts": now,
        "last_seen_ts": now
    }

    with state_lock:
        # Try to aggregate with an existing alert of the same key
        merged = False
        for existing in state["alerts"]:
            if existing.get("agg_key") == agg_key:
                existing["pkt_count"] += 1
                existing["time"] = now_str
                existing["last_seen"] = now_str
                existing["last_seen_ts"] = now
                existing["risk"] = max(existing["risk"], risk)
                # Calculate duration in seconds
                duration = int(now - existing["first_seen_ts"])
                existing["duration"] = duration
                merged = True
                break
        if not merged:
            state["alerts"].insert(0, alert_entry)
            if len(state["alerts"]) > 100:
                state["alerts"].pop()

        if attack_type == "ARP": state["counters"]["arp_attacks"] += 1
        elif attack_type == "DHCP": state["counters"]["dhcp_attacks"] += 1
        elif attack_type == "DNS": state["counters"]["dns_attacks"] += 1
        elif attack_type == "ML": state["counters"]["ml_anomalies"] += 1
        elif attack_type == "SCAN": state["counters"]["port_scans"] += 1

    color = config.Colors.WARNING if risk < 7 else config.Colors.FAIL
    print(f"{color}[{attack_type} DETECTED] Risk {risk}: {message}{config.Colors.ENDC}")
    logging.warning(f"[{attack_type}] Risk {risk}: {message}")

    if packet and risk >= 7:
        try:
            wrpcap("suspicious.pcap", packet, append=True)
        except Exception as e:
            logging.error(f"Failed to log packet to PCAP: {e}")

    if config.AUTO_BLOCK_ENABLED and risk >= config.RISK_SCORE_THRESHOLD and src_mac:
        block_attacker(src_mac)
        # Update status to BLOCKED
        with state_lock:
            for a in state["alerts"]:
                if a.get("agg_key") == agg_key:
                    a["status"] = "BLOCKED"
                    break
    elif risk < config.RISK_SCORE_THRESHOLD:
        # Low risk = monitoring only
        with state_lock:
            for a in state["alerts"]:
                if a.get("agg_key") == agg_key and a["status"] == "ACTIVE":
                    a["status"] = "MONITORING"
                    break

def block_attacker(mac_address):
    with state_lock:
        if mac_address in state["blocked_macs"]:
            return  # Already blocked
        state["blocked_macs"].add(mac_address)
        
    os_name = platform.system()
    print(f"{config.Colors.FAIL}[AUTO-DEFENSE] Blocking MAC {mac_address} ({os_name} mode){config.Colors.ENDC}")
    logging.info(f"Blocking attacker MAC: {mac_address}")
    
    try:
        if os_name == "Linux":
            # Real iptables block on Linux (requires root and mac module)
            subprocess.run(["iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac_address, "-j", "DROP"], check=True)
        elif os_name == "Windows":
            # Windows Firewall doesn't natively support blocking by MAC address easily.
            # We resolve the MAC to its IP address and block the IP using netsh.
            attacker_ip = None
            with state_lock:
                for ip, mac in state["arp_table"].items():
                    if mac.lower() == mac_address.lower():
                        attacker_ip = ip
                        break
            
            if attacker_ip:
                try:
                    # Inbound block rule
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=NetworkDetector_Block_{attacker_ip}",
                        "dir=in", "action=block", f"remoteip={attacker_ip}"
                    ], check=True, capture_output=True)
                    # Outbound block rule
                    subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=NetworkDetector_Block_{attacker_ip}",
                        "dir=out", "action=block", f"remoteip={attacker_ip}"
                    ], check=True, capture_output=True)
                    logging.info(f"Windows Firewall rule created: Blocked IP {attacker_ip} (associated with MAC {mac_address})")
                    print(f"{config.Colors.FAIL}[AUTO-DEFENSE] Windows Firewall blocked IP {attacker_ip} for MAC {mac_address}{config.Colors.ENDC}")
                except subprocess.CalledProcessError as err:
                    err_msg = err.stderr.decode('utf-8', errors='ignore') if err.stderr else str(err)
                    logging.error(f"Failed to execute Windows Firewall block command (needs Administrator privileges): {err_msg}")
                    print(f"{config.Colors.WARNING}[WARNING] Windows Firewall command failed. Did you run the tool as Administrator? Details: {err_msg.strip()}{config.Colors.ENDC}")
                except Exception as e:
                    logging.error(f"Unexpected error applying Windows firewall block: {e}")
            else:
                logging.info(f"Windows mode: Block action simulated for MAC {mac_address} (no IP resolved).")
                print(f"{config.Colors.OKCYAN}[INFO] Windows mode: Block simulated for {mac_address} (could not resolve to IP address).{config.Colors.ENDC}")
    except Exception as e:
        logging.error(f"Failed to block attacker {mac_address}: {str(e)}")

# --- Gratuitous ARP (GARP) Detection Module ---
# GARP = ARP packet where sender IP == target IP (unsolicited IP-MAC announcement).
# Since ARP has no authentication field, GARP is the primary vector for ARP cache poisoning.
# This module detects: Gateway impersonation, flood attacks, unknown sources, IP conflicts.
def analyze_garp(packet, src_ip, src_mac):
    """
    Dedicated Gratuitous ARP detection engine.
    Returns True if a critical attack was detected (caller should skip normal ARP processing).
    Returns False if no critical issue found (caller continues with standard checks).
    """
    now = time.time()

    # --- CHECK 1: GARP Gateway Impersonation (CRITICAL - Risk 10) ---
    # Any GARP claiming to be the gateway IP but from a different MAC is a direct attack.
    # This is the most dangerous form of ARP poisoning — hijacking the default gateway.
    if src_ip == config.GATEWAY_IP:
        with state_lock:
            known_gw_mac = state["arp_table"].get(config.GATEWAY_IP)
        if known_gw_mac and known_gw_mac != src_mac:
            msg = (f"CRITICAL: Gratuitous ARP Gateway Impersonation! "
                   f"GARP broadcast claims Gateway IP {src_ip} belongs to MAC {src_mac}, "
                   f"but legitimate Gateway MAC is {known_gw_mac}")
            add_alert("ARP", msg, risk=10, src_mac=src_mac, packet=packet, attacker_ip=src_ip)
            active_probe(src_ip, src_mac, known_gw_mac, packet)
            return True

    # --- CHECK 2: GARP Flood Detection (Risk 9) ---
    # An attacker performing ARP cache poisoning sends rapid GARPs (>5 in 10 seconds)
    # to continuously overwrite victims' ARP caches before they can recover.
    garp_flood_tracker[src_mac] = [ts for ts in garp_flood_tracker[src_mac] if now - ts < 10]
    garp_flood_tracker[src_mac].append(now)

    if len(garp_flood_tracker[src_mac]) > 5:
        msg = (f"GARP Flood Attack detected! MAC {src_mac} sent "
               f"{len(garp_flood_tracker[src_mac])} Gratuitous ARP packets in 10 seconds "
               f"for IP {src_ip}")
        add_alert("ARP", msg, risk=9, src_mac=src_mac, packet=packet, attacker_ip=src_ip)
        # Reset to last 2 entries to avoid continuous alert spam
        garp_flood_tracker[src_mac] = garp_flood_tracker[src_mac][-2:]
        return True

    # --- CHECK 3: GARP IP Conflict Detection (Risk 8) ---
    # GARP announcing an IP that is already assigned to a different MAC in our ARP table.
    # This is a direct indicator of ARP cache poisoning — the attacker is trying to
    # steal another host's IP identity.
    with state_lock:
        existing_mac = state["arp_table"].get(src_ip)
    if existing_mac and existing_mac != src_mac:
        msg = (f"GARP IP Conflict detected! Gratuitous ARP claims IP {src_ip} "
               f"belongs to MAC {src_mac}, but ARP table shows it belongs to {existing_mac}")
        add_alert("ARP", msg, risk=8, src_mac=src_mac, packet=packet, attacker_ip=src_ip)
        active_probe(src_ip, src_mac, existing_mac, packet)
        return True

    # --- CHECK 4: GARP from Unknown/New Device (Risk 7) ---
    # A GARP from a MAC address never seen before on the network is suspicious.
    # Legitimate devices typically send normal ARP requests first, not unsolicited GARPs.
    if src_mac not in known_network_macs:
        elapsed = now - start_time
        # Only alert after the initial 60-second learning phase to avoid startup noise
        if elapsed > 60:
            msg = (f"Suspicious GARP from unknown device — MAC {src_mac} sent a "
                   f"Gratuitous ARP for IP {src_ip} but was never seen on this network before")
            add_alert("ARP", msg, risk=7, src_mac=src_mac, packet=packet, attacker_ip=src_ip)
            # Don't return True — allow normal ARP processing to learn this MAC

    return False  # No critical attack, continue with standard ARP analysis

# --- Deep Packet Structure Validation ---
def validate_arp_structure(packet):
    """
    Validates structural and semantic rules of ARP packets.
    Returns True if an anomaly is found (and alerts), False otherwise.
    """
    if not packet.haslayer(ARP):
        return False
        
    arp = packet[ARP]
    
    # Check 1: Ethernet Source MAC vs ARP Sender MAC mismatch
    try:
        from scapy.layers.l2 import Ether
        if packet.haslayer(Ether):
            eth_src = packet[Ether].src.lower()
            arp_src = arp.hwsrc.lower() if arp.hwsrc else ""
            if eth_src and arp_src and eth_src != arp_src:
                msg = f"Deep Packet Anomaly: Ethernet Frame source MAC ({eth_src}) does not match inner ARP Sender MAC ({arp_src})!"
                add_alert("ARP", msg, risk=8, src_mac=eth_src, packet=packet)
                return True
    except Exception as e:
        logging.error(f"Error checking Ethernet source MAC: {e}")
        
    # Check 2: Invalid ARP fields (standard Ethernet + IPv4 values)
    # hwtype = 1 (Ethernet), ptype = 2048 (0x0800 IPv4), hwlen = 6, plen = 4
    if arp.hwtype != 1 or arp.ptype != 2048 or arp.hwlen != 6 or arp.plen != 4:
        msg = (f"Deep Packet Anomaly: Malformed ARP Header fields! "
               f"HWType: {arp.hwtype} (expected 1), PType: {arp.ptype} (expected 2048), "
               f"HWLen: {arp.hwlen} (expected 6), PLen: {arp.plen} (expected 4)")
        add_alert("ARP", msg, risk=7, src_mac=arp.hwsrc, packet=packet)
        return True
        
    # Check 3: Broadcast or Multicast MAC as unicast Sender
    src_mac = arp.hwsrc.lower() if arp.hwsrc else ""
    if src_mac == "ff:ff:ff:ff:ff:ff" or src_mac.startswith("01:00:5e"):
        msg = f"Deep Packet Anomaly: ARP claims Sender MAC is a broadcast/multicast address ({src_mac})!"
        add_alert("ARP", msg, risk=8, src_mac=src_mac, packet=packet)
        return True
        
    return False

# --- Active Probing (Background Verification) ---
def active_probe(ip, reported_mac, old_mac, packet):
    """
    Asynchronously sends an ARP request probe to verify mapping conflicts.
    If multiple MACs reply, or if only the original MAC replies, confirms the attack.
    """
    if not config.ACTIVE_PROBING_ENABLED:
        logging.info(f"[Active Probe] Active probing is disabled. Skipping validation for IP {ip}")
        return

    def probe_worker():
        try:
            from scapy.all import Ether, ARP, srp
            logging.info(f"[Active Probe] Starting verification probe for IP {ip}...")
            print(f"{config.Colors.OKCYAN}[INFO] Active Probe: Verifying IP {ip}...{config.Colors.ENDC}")
            
            # Craft broadcast ARP request to trigger responses from all hosts claiming the IP
            probe_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip)
            
            # Send and receive packets (wait up to 2.0 seconds)
            answered, unanswered = srp(probe_pkt, timeout=2.0, verbose=False)
            
            replies = []
            for snd, rcv in answered:
                if rcv.haslayer(ARP):
                    replies.append(rcv[ARP].hwsrc.lower())
                    
            if not replies:
                logging.info(f"[Active Probe] No responses to verification probe for IP {ip}")
                return
                
            unique_macs = set(replies)
            logging.info(f"[Active Probe] Received {len(replies)} response(s) for IP {ip}: {list(unique_macs)}")
            
            if len(unique_macs) > 1:
                # Multiple devices claimed this IP address! Definitive MitM / Spoofing attack
                msg = (f"ACTIVE PROBE CONFIRMED ATTACK: IP {ip} is claimed by multiple active devices! "
                       f"Responding MACs: {', '.join(unique_macs)}")
                add_alert("ARP", msg, risk=10, attacker_ip=ip, packet=packet)
            elif old_mac and old_mac.lower() in unique_macs and reported_mac.lower() not in unique_macs:
                # Only the legitimate owner responded; the attacker's claimed mapping was spoofed
                msg = (f"ACTIVE PROBE CONFIRMED ATTACK: IP {ip} responded only with legitimate MAC {old_mac}. "
                       f"The reported MAC {reported_mac} was not active for this IP.")
                add_alert("ARP", msg, risk=10, src_mac=reported_mac, packet=packet, attacker_ip=ip)
            else:
                logging.info(f"[Active Probe] Verification complete. IP {ip} mapped to {replies[0]}")
                # Legitimate change confirmed by active probing (only new MAC responded)
                with state_lock:
                    state["arp_table"][ip] = reported_mac.lower()
                db_set_mac(ip, reported_mac.lower())
        except Exception as e:
            logging.error(f"Active probing failed for IP {ip}: {e}")

    threading.Thread(target=probe_worker, daemon=True).start()

# --- ARP Spoofing Detection (Hardened + GARP-Aware) ---
def analyze_arp(packet):
    if packet.haslayer(ARP):
        # 0. Deep Packet Structure Validation
        if validate_arp_structure(packet):
            return

        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc.lower() if packet[ARP].hwsrc else ""
        if not src_mac or src_mac == "00:00:00:00:00:00":
            return

        # Track all observed MACs on the network for GARP unknown-source detection
        known_network_macs.add(src_mac)

        # 1. Prevent false positives from VRRP/HSRP failovers in enterprise networks
        if src_mac.startswith("00:00:5e:00:01") or src_mac.startswith("00:00:0c:07:ac"):
            return

        # --- Check 1: Self-IP Impersonation (Attacker claims to be US) ---
        global our_ip, our_mac
        if our_ip and src_ip == our_ip:
            if src_mac != our_mac:
                msg = f"CRITICAL: ARP Spoofing/Self-IP Impersonation! Device with MAC {src_mac} is claiming our interface IP {our_ip} (our real MAC is {our_mac})!"
                add_alert("ARP", msg, risk=10, src_mac=src_mac, packet=packet, attacker_ip=src_ip)
                return

        # --- Check 2: Gateway IP Impersonation ---
        if src_ip == config.GATEWAY_IP and (our_ip != config.GATEWAY_IP):
            with state_lock:
                known_gw_mac = state["arp_table"].get(config.GATEWAY_IP)
            if known_gw_mac and known_gw_mac != src_mac:
                msg = f"CRITICAL: Gateway IP Impersonation! Device with MAC {src_mac} is claiming Gateway IP {src_ip} (real Gateway MAC is {known_gw_mac})!"
                add_alert("ARP", msg, risk=10, src_mac=src_mac, packet=packet, attacker_ip=src_ip)
                active_probe(src_ip, src_mac, known_gw_mac, packet)
                return

        # --- Check 3: Gratuitous ARP (GARP) Detection ---
        # GARP = ARP packet where sender IP == target IP (unsolicited announcement)
        target_ip = packet[ARP].pdst
        if src_ip == target_ip and src_ip != "0.0.0.0":
            garp_blocked = analyze_garp(packet, src_ip, src_mac)
            if garp_blocked:
                return  # Attack detected and handled by GARP module

        # --- Check 4: General IP-MAC Mapping Conflict Detection (For Requests & Replies) ---
        with state_lock:
            existing_mac = state["arp_table"].get(src_ip)

        if existing_mac and existing_mac != src_mac:
            # Conflict detected!
            now = time.time()
            with state_lock:
                history = arp_history[src_ip]
                history = [x for x in history if now - x[1] < 20]
                history.append((src_mac, now))
                arp_history[src_ip] = history
                
                # Count transitions
                transitions = 0
                last_mac = history[0][0]
                for mac, ts in history[1:]:
                    if mac != last_mac:
                        transitions += 1
                        last_mac = mac

            # Determine risk and message
            if src_ip == config.GATEWAY_IP:
                msg = f"Gateway ARP Spoofing detected! Default Gateway IP {src_ip} changed MAC from {existing_mac} to {src_mac}"
                risk_score = 10
            elif transitions >= 2:
                msg = f"ARP Spoofing (Flip-Flop) Confirmed! Client IP {src_ip} is rapidly changing MAC (transitions: {transitions} in 20s between {existing_mac} and {src_mac})"
                risk_score = 9
            else:
                msg = f"Potential ARP Spoofing / IP Conflict! IP {src_ip} is claimed by MAC {src_mac}, but is registered to {existing_mac}"
                risk_score = 8

            add_alert("ARP", msg, risk=risk_score, src_mac=src_mac, packet=packet, attacker_ip=src_ip)
            active_probe(src_ip, src_mac, existing_mac, packet)
            # We do NOT update the arp_table/database yet to prevent the attacker from silently overwriting the mapping.
            # The active_probe worker will update it if only the new MAC responds to the probe.
            return

        # No conflict: Update/insert the mapping in state and database
        with state_lock:
            state["arp_table"][src_ip] = src_mac
        db_set_mac(src_ip, src_mac)

# --- DHCP Spoofing Detection (Hardened Learning Phase) ---
known_dhcp_servers = set(mac.lower() for mac in config.AUTHORIZED_DHCP_MACS)

def analyze_dhcp(packet):
    if packet.haslayer(DHCP) and packet.haslayer(BOOTP):
        dhcp_options = packet[DHCP].options
        for opt in dhcp_options:
            if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] == 2:  # DHCPOFFER
                from scapy.layers.l2 import Ether
                src_mac = packet[Ether].src.lower() if packet.haslayer(Ether) else None
                if not src_mac: continue
                
                # Check if it is a pre-configured authorized MAC
                if config.AUTHORIZED_DHCP_MACS and src_mac in (m.lower() for m in config.AUTHORIZED_DHCP_MACS):
                    return
                
                elapsed = time.time() - start_time
                learning_phase = elapsed < config.ML_BASELINE_DURATION
                
                if learning_phase:
                    if src_mac not in known_dhcp_servers:
                        known_dhcp_servers.add(src_mac)
                        logging.info(f"[LEARNING PHASE] Learned legitimate DHCP server: {src_mac} (active for {int(config.ML_BASELINE_DURATION - elapsed)}s more)")
                else:
                    # Learning phase is over, strict validation
                    if config.AUTHORIZED_DHCP_MACS and src_mac not in (m.lower() for m in config.AUTHORIZED_DHCP_MACS):
                        msg = f"Rogue DHCP Server detected! MAC {src_mac} offered an IP, not in pre-configured authorized list."
                        add_alert("DHCP", msg, risk=9, src_mac=src_mac, packet=packet)
                    elif src_mac not in known_dhcp_servers:
                        msg = f"Rogue DHCP Server detected! MAC {src_mac} offered an IP after baseline learning phase. Known servers: {known_dhcp_servers}"
                        add_alert("DHCP", msg, risk=9, src_mac=src_mac, packet=packet)

# --- DNS Spoofing Detection (Responder-Based) ---
# Instead of comparing resolved IPs (false positives from CDNs/load balancers),
# we track WHO sends the DNS response. Real spoofing = response from untrusted source.
dns_transactions = {}
learned_dns_servers = set()  # Auto-learned trusted DNS responders

def analyze_dns(packet):
    if packet.haslayer(DNS):
        dns = packet[DNS]

        # --- Track DNS queries for the dashboard ---
        if dns.qr == 1 and packet.haslayer(DNSRR):  # DNS Response
            qname = dns.qd.qname.decode('utf-8') if dns.qd else "Unknown"
            if qname.endswith('.'): qname = qname[:-1]

            with state_lock:
                if qname != "Unknown" and qname not in state["recent_dns"]:
                    state["recent_dns"].insert(0, qname)
                    if len(state["recent_dns"]) > 10:
                        state["recent_dns"].pop()

            # --- Responder-Based Spoof Detection ---
            if not config.DNS_SPOOF_DETECTION_ENABLED:
                return

            # Get the IP of whoever sent this DNS response
            responder_ip = packet[IP].src if packet.haslayer(IP) else None
            if not responder_ip:
                return

            from scapy.layers.l2 import Ether
            responder_mac = packet[Ether].src if packet.haslayer(Ether) else None
            tx_id = dns.id

            # Determine trusted servers (config or auto-learned)
            trusted = config.TRUSTED_DNS_SERVERS if config.TRUSTED_DNS_SERVERS else learned_dns_servers

            if len(trusted) == 0:
                # First DNS response ever — learn this server as trusted
                learned_dns_servers.add(responder_ip)
                logging.info(f"Auto-learned trusted DNS server: {responder_ip}")
                return

            # CHECK 1: Is the responder a trusted DNS server?
            if responder_ip not in trusted:
                msg = f"DNS spoofing attempt detected — response for {qname} from untrusted server {responder_ip}"
                add_alert("DNS", msg, risk=8, src_mac=responder_mac, packet=packet,
                          attacker_ip=responder_ip, protocol="UDP")
                return

            # CHECK 2: Race condition — two responses for same TXID from different sources
            if tx_id in dns_transactions:
                prev_responder, prev_mac, timestamp = dns_transactions[tx_id]
                if prev_responder != responder_ip and (time.time() - timestamp) < 2:
                    msg = f"DNS race condition detected — TXID {tx_id} for {qname} answered by {prev_responder} AND {responder_ip}"
                    attacker = responder_ip if responder_ip not in trusted else prev_responder
                    attacker_mac = responder_mac if responder_ip not in trusted else prev_mac
                    add_alert("DNS", msg, risk=9, src_mac=attacker_mac, packet=packet,
                              attacker_ip=attacker, protocol="UDP")
            else:
                dns_transactions[tx_id] = (responder_ip, responder_mac, time.time())

            # Cleanup old transactions
            if len(dns_transactions) > 1000:
                oldest_keys = list(dns_transactions.keys())[:500]
                for k in oldest_keys: del dns_transactions[k]

# --- ML Anomaly Detection (Time-Windowed) ---
ml_model = IsolationForest(contamination=config.ML_CONTAMINATION, random_state=42)
ml_training_buffer = []
is_model_trained = False

def ml_worker():
    global is_model_trained, start_time
    while True:
        time.sleep(config.ML_WINDOW_SIZE)
        
        # Extract and reset window metrics
        with ml_window_lock:
            features = {
                'packet_rate': current_window["packets"] / config.ML_WINDOW_SIZE,
                'dns_rate': current_window["dns_queries"] / config.ML_WINDOW_SIZE,
                'unique_ips': len(current_window["ips"])
            }
            current_window["packets"] = 0
            current_window["dns_queries"] = 0
            current_window["ips"].clear()

        elapsed_time = time.time() - start_time
        
        if not is_model_trained:
            if elapsed_time < config.ML_BASELINE_DURATION:
                remaining = int(config.ML_BASELINE_DURATION - elapsed_time)
                with state_lock:
                    state["ml_status"] = f"Learning normal traffic... ({remaining}s)"
                ml_training_buffer.append(list(features.values()))
            else:
                # Time to train
                if len(ml_training_buffer) > 0:
                    df = pd.DataFrame(ml_training_buffer, columns=features.keys())
                    ml_model.fit(df)
                    is_model_trained = True
                    with state_lock:
                        state["ml_status"] = "Active"
                    print(f"{config.Colors.OKGREEN}[ML] Isolation Forest trained on {len(ml_training_buffer)} time windows.{config.Colors.ENDC}")
                    logging.info("ML Model trained on baseline traffic windows.")
                else:
                    # Reset timer if no packets were seen
                    start_time = time.time()
        else:
            # Predict
            X = pd.DataFrame([features.values()], columns=features.keys())
            pred = ml_model.predict(X)[0]
            if pred == -1:
                score = ml_model.decision_function(X)[0]
                if score < -0.15:
                    msg = f"Traffic Anomaly Detected (Time Window)! Packet Rate: {features['packet_rate']:.1f}/s, Score: {score:.3f}"
                    add_alert("ML", msg, risk=5)

# --- Port Scan / SYN Flood Detection ---
# Tracks SYN packets per IP within a time window
syn_tracker = defaultdict(lambda: {"count": 0, "first_seen": time.time(), "ports": set()})

def analyze_port_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        # Check if it's just a SYN packet (flag == 2 or flag == 'S')
        if packet[TCP].flags == "S":
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            tracker = syn_tracker[src_ip]
            current_time = time.time()
            
            # Reset window if older than 10 seconds
            if current_time - tracker["first_seen"] > 10:
                tracker["count"] = 0
                tracker["first_seen"] = current_time
                tracker["ports"].clear()
                
            tracker["count"] += 1
            tracker["ports"].add(dst_port)
            
            # Detect SYN flood or Port Scan (e.g., > 20 SYNs to > 5 different ports in 10s)
            if tracker["count"] > 20 and len(tracker["ports"]) > 5:
                from scapy.layers.l2 import Ether
                src_mac = packet[Ether].src if packet.haslayer(Ether) else None
                msg = f"Port Scan/SYN Flood detected from {src_ip}! {tracker['count']} SYNs to {len(tracker['ports'])} ports."
                add_alert("SCAN", msg, risk=7, src_mac=src_mac, packet=packet)
                # Reset to avoid spamming
                tracker["count"] = -100

# --- Main Packet Handler ---
def packet_callback(packet):
    if config.DEBUG_MODE:
        print(packet.summary())
        
    with state_lock:
        state["counters"]["packets_processed"] += 1
        if packet.haslayer(DNS): state["counters"]["dns_packets"] += 1
        if packet.haslayer(ARP): state["counters"]["arp_packets"] += 1
        if packet.haslayer(UDP): state["counters"]["udp_packets"] += 1
        if packet.haslayer(ICMP): state["counters"]["icmp_packets"] += 1

    with ml_window_lock:
        current_window["packets"] += 1
        if packet.haslayer(DNS): current_window["dns_queries"] += 1
        if packet.haslayer(IP): current_window["ips"].add(packet[IP].src)

    try:
        analyze_arp(packet)
        analyze_dhcp(packet)
        analyze_dns(packet)
        # Port scan and ML detection disabled - focusing on ARP/DHCP/DNS spoofing only
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def start_sniffer(iface=None):
    global our_ip, our_mac
    # Initialize SQLite database and load existing mappings
    try:
        init_db()
        conn = sqlite3.connect("network_detector.db")
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac FROM arp_mappings")
        rows = cursor.fetchall()
        with state_lock:
            for ip, mac in rows:
                state["arp_table"][ip] = mac
        conn.close()
        logging.info(f"Loaded {len(rows)} persistent ARP mappings from database.")
        print(f"{config.Colors.OKCYAN}[INFO] Database: Loaded {len(rows)} persistent ARP mappings.{config.Colors.ENDC}")
    except Exception as e:
        logging.error(f"Failed to load persistent ARP mappings: {e}")

    # Get local interface IP and MAC dynamically
    try:
        from scapy.all import get_if_hwaddr, get_if_addr, conf
        active_iface = iface if iface else conf.iface
        our_mac = get_if_hwaddr(active_iface).lower()
        our_ip = get_if_addr(active_iface)
        logging.info(f"Sniffer binding - Interface: {active_iface}, IP: {our_ip}, MAC: {our_mac}")
        print(f"{config.Colors.OKCYAN}[INFO] Sniffer binding - IP: {our_ip}, MAC: {our_mac}{config.Colors.ENDC}")
    except Exception as e:
        logging.error(f"Failed to get MAC/IP for interface {active_iface}: {e}")

    with state_lock:
        state["sensor"]["interface"] = iface if iface else "Default"
        state["sensor"]["capture_active"] = True
        
        # Detect environment with richer info
        def detect_environment():
            os_name = platform.system()
            try:
                # Check OS release/version
                if os_name == "Windows":
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                    build = winreg.QueryValueEx(key, "CurrentBuild")[0]
                    product = winreg.QueryValueEx(key, "ProductName")[0]
                    winreg.CloseKey(key)
                    # Shorten product name
                    version = product.replace("Microsoft ", "").replace(" Pro", "").replace(" Home", "")
                else:
                    version = os_name

                # Detect VM by checking adapter names
                vm_hint = ""
                try:
                    result = subprocess.run(
                        ["ipconfig"] if os_name == "Windows" else ["ip", "link"],
                        capture_output=True, text=True, timeout=3)
                    output = result.stdout.lower()
                    if "vmware" in output or "vmnet" in output:
                        vm_hint = " · VMware"
                    elif "virtualbox" in output or "vboxnet" in output:
                        vm_hint = " · VirtualBox"
                    elif "hyper-v" in output or "vethernet" in output:
                        vm_hint = " · Hyper-V"
                except Exception:
                    pass

                # Detect wireless vs wired
                iface_hint = ""
                if not vm_hint:
                    try:
                        result2 = subprocess.run(
                            ["ipconfig"] if os_name == "Windows" else ["ip", "link"],
                            capture_output=True, text=True, timeout=3)
                        out2 = result2.stdout.lower()
                        if "wireless" in out2 or "wi-fi" in out2 or "wlan" in out2:
                            iface_hint = " · Wi-Fi"
                        elif "ethernet" in out2:
                            iface_hint = " · Ethernet"
                    except Exception:
                        pass

                return f"{version}{vm_hint}{iface_hint}"
            except Exception:
                return os_name

        state["sensor"]["environment"] = detect_environment()

    # Try to auto-detect gateway IP dynamically using Scapy
    try:
        from scapy.all import conf
        route = conf.route.route("8.8.8.8")
        if route and len(route) >= 3 and route[1] and route[1] != "0.0.0.0":
            config.GATEWAY_IP = route[1]
            logging.info(f"Auto-detected Default Gateway: {config.GATEWAY_IP}")
            print(f"{config.Colors.OKCYAN}[INFO] Auto-detected Default Gateway: {config.GATEWAY_IP}{config.Colors.ENDC}")
    except Exception as e:
        logging.warning(f"Could not dynamically auto-detect default gateway: {e}")

    iface_str = f" on {iface}" if iface else ""
    print(f"{config.Colors.OKBLUE}Starting Network Attack Detector Sniffer{iface_str}...{config.Colors.ENDC}")
    
    # ML worker thread disabled - focusing on ARP/DHCP/DNS spoofing only
    # threading.Thread(target=ml_worker, daemon=True).start()
    
    # Using store=0 to avoid memory leak
    sniff(prn=packet_callback, store=0, iface=iface)

if __name__ == "__main__":
    start_sniffer()
