import threading
import argparse
from flask import Flask, jsonify, render_template

import detector

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    with detector.state_lock:
        data = {
            "counters": detector.state["counters"],
            "blocked_count": len(detector.state["blocked_macs"]),
            "arp_table_size": len(detector.state["arp_table"]),
            "sensor": detector.state["sensor"],
            "recent_dns": detector.state["recent_dns"],
            "ml_status": detector.state["ml_status"]
        }
    return jsonify(data)

@app.route('/api/history')
def api_history():
    with detector.state_lock:
        # Return a copy of the list
        history = list(detector.state["alerts"])
    return jsonify(history)

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "detector_running": sniffer_thread.is_alive()})

@app.route('/api/simulate/<attack_type>', methods=['POST'])
def api_simulate(attack_type):
    if attack_type == 'arp':
        detector.add_alert("ARP", "ARP spoofing attempt detected — IP 192.168.1.1 changed MAC from 11:22:33:44:55:66 to aa:bb:cc:dd:ee:ff", risk=8,
            src_mac="aa:bb:cc:dd:ee:ff", attacker_ip="192.168.1.50", victim_ip="192.168.1.1",
            victim_mac="11:22:33:44:55:66", protocol="ARP")
    elif attack_type == 'dns':
        detector.add_alert("DNS", "DNS spoofing attempt detected — TXID 48291 for google.com resolved to 1.1.1.1 AND 93.184.216.34", risk=7,
            src_mac="aa:bb:cc:dd:ee:ff", attacker_ip="10.0.0.99", victim_ip="192.168.1.10",
            victim_mac="11:22:33:44:55:66", protocol="UDP")
    elif attack_type == 'dhcp':
        detector.add_alert("DHCP", "Rogue DHCP server detected — unauthorized DHCPOFFER from unknown server", risk=9,
            src_mac="ff:ee:dd:cc:bb:aa", attacker_ip="192.168.1.200", victim_ip="255.255.255.255",
            victim_mac="ff:ff:ff:ff:ff:ff", protocol="UDP")
    elif attack_type == 'garp':
        detector.add_alert("ARP", "CRITICAL: Gratuitous ARP Gateway Impersonation! GARP broadcast claims Gateway IP 192.168.1.1 belongs to MAC aa:bb:cc:dd:ee:ff, but legitimate Gateway MAC is 11:22:33:44:55:66", risk=10,
            src_mac="aa:bb:cc:dd:ee:ff", attacker_ip="192.168.1.1", victim_ip="192.168.1.1",
            victim_mac="ff:ff:ff:ff:ff:ff", protocol="ARP")
    else:
        return jsonify({"status": "error", "message": "Unsupported attack type. Supported: arp, dns, dhcp, garp"}), 400
    return jsonify({"status": "success", "simulated": attack_type})

def start_app():
    # We must run app in main thread to avoid some windows threading issues with flask reloader
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Network Attack Detector")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., eth0, wlan0)", default=None)
    args = parser.parse_args()

    # Start detector in a background thread
    sniffer_thread = threading.Thread(target=detector.start_sniffer, args=(args.interface,), daemon=True)
    sniffer_thread.start()
    
    iface_msg = f"on interface {args.interface}" if args.interface else "on default interface"
    print(f"Web dashboard starting at http://localhost:5000 ({iface_msg})")
    start_app()
