import os
import logging

# ==========================================
# Network Attack Detector Configuration
# ==========================================

# 1. ARP Spoofing Configuration
# Minimal False Positives: Only alert if an existing IP changes its MAC address
# and we haven't seen the new MAC before, or if it's claiming to be the gateway.
GATEWAY_IP = os.getenv("GATEWAY_IP", "192.168.1.1")
GATEWAY_MAC = os.getenv("GATEWAY_MAC", "")  # Set this if known to prevent spoofing the gateway

# 2. DHCP Spoofing Configuration
# Minimal False Positives: List of MAC addresses allowed to send DHCPOFFERs.
# If empty, the first DHCP server seen will be logged, and subsequent different ones will trigger an alert.
AUTHORIZED_DHCP_MACS = set(os.getenv("AUTHORIZED_DHCP_MACS", "").split(","))
AUTHORIZED_DHCP_MACS.discard("")

# 3. DNS Spoofing Configuration
# Professional Detection: Instead of comparing resolved IPs (causes false positives with CDNs),
# we track WHO responds to DNS queries. If a response comes from an untrusted source, it's suspicious.
# If empty, the system will auto-learn the first DNS server seen and alert on new ones.
DNS_SPOOF_DETECTION_ENABLED = True
TRUSTED_DNS_SERVERS = set(filter(None, os.getenv("TRUSTED_DNS_SERVERS", "").split(",")))

# 4. ML Anomaly Detection Configuration
# Minimal False Positives: Learn traffic baselines over a window of time before activating.
ML_BASELINE_DURATION = 120  # Learn for the first 120 seconds
ML_WINDOW_SIZE = 10         # Analyze traffic every 10 seconds
ML_CONTAMINATION = 0.01     # Expected proportion of outliers in the data

# How often (seconds) to re-probe known ARP mappings when active probing is enabled
REPROBE_INTERVAL = int(os.getenv("REPROBE_INTERVAL", "300"))  # 5 minutes by default

# GARP tuning and allowlist
GARP_DETECTION_ENABLED = os.getenv("GARP_DETECTION_ENABLED", "True").lower() in ("true", "1", "yes")
GARP_ALLOWLIST = set(filter(None, os.getenv("GARP_ALLOWLIST", "").split(",")))
GARP_FLOOD_THRESHOLD = int(os.getenv("GARP_FLOOD_THRESHOLD", "5"))
GARP_FLOOD_WINDOW = int(os.getenv("GARP_FLOOD_WINDOW", "10"))

# Flip-flop tuning
FLIP_FLOP_TRANSITIONS = int(os.getenv("FLIP_FLOP_TRANSITIONS", "2"))
DHCP_FLIPFLOP_SUPPRESSION = int(os.getenv("DHCP_FLIPFLOP_SUPPRESSION", "30"))

# Deep packet strict mode: when False, relax Ether-vs-ARP strict mismatch alerts
DEEP_PACKET_STRICT = os.getenv("DEEP_PACKET_STRICT", "False").lower() in ("true", "1", "yes")

# DNS race window (seconds)
DNS_RACE_WINDOW = int(os.getenv("DNS_RACE_WINDOW", "2"))

# 5. Auto-Defense Configuration
AUTO_BLOCK_ENABLED = os.getenv("AUTO_BLOCK_ENABLED", "True").lower() in ("true", "1", "yes")
RISK_SCORE_THRESHOLD = 7
DEBUG_MODE = os.getenv("DEBUG_MODE", "True").lower() in ("true", "1", "yes")

# 6. Security Hardening Configuration
# Set to True only in authorized networks or test environments to allow active ARP verification.
ACTIVE_PROBING_ENABLED = os.getenv("ACTIVE_PROBING_ENABLED", "False").lower() in ("true", "1", "yes")

# Mitigation mode: 'block' will attempt active blocking (iptables/netsh), 'log' will only record incidents
MITIGATION_MODE = os.getenv("MITIGATION_MODE", "block").lower()

# 6. Logging
LOG_FILE = "detector.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)

# Colors for console output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
