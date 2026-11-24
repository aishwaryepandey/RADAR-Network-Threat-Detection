Runbook — Network Detector

Prerequisites
- Linux/WSL preferred for packet capture; running as root or with appropriate capabilities required.
- Python 3.11+ recommended. Use a virtualenv (example below).

Setup
1. Create venv and install deps:

```bash
python -m venv ~/ndenv
source ~/ndenv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

2. Allow non-root packet capture (optional, Linux):

```bash
# Replace the path with your Python executable in the venv, e.g. ~/ndenv/bin/python
sudo setcap cap_net_raw,cap_net_admin=eip ~/ndenv/bin/python
```

If you use Kali or a distro with "externally managed" packages, prefer running venv inside WSL or a user-writable home directory.

Running
- To run with privileged sniffing (recommended):

```bash
sudo ~/ndenv/bin/python app.py
```

- Or run as normal user if you set `setcap` on the venv Python executable.

Configuration
- Use environment variables or `config.py` to tune behavior.
  - `GATEWAY_IP` — default gateway IP (auto-detected if unset).
  - `GATEWAY_MAC` — pin gateway MAC to prevent impersonation.
  - `ACTIVE_PROBING_ENABLED` — enable active ARP verification (default: False).
  - `REPROBE_INTERVAL` — seconds between periodic re-probes (default: 300).
  - `MITIGATION_MODE` — `block` to actively block (iptables/netsh) or `log` for monitoring-only.
  - `AUTO_BLOCK_ENABLED` — master enable for auto-blocking rules.

Testing
- Use an isolated lab (VMs or isolated VLAN) when enabling `ACTIVE_PROBING_ENABLED` or auto-blocking.
- To test gateway pinning:
  - Set `GATEWAY_MAC` to the router's MAC in the environment or `config.py`.
  - Generate a gratuitous ARP claiming the gateway from a different VM and verify an alert appears in the dashboard and that `active_probe` runs.

Troubleshooting
- If you see "permission denied" from Scapy or raw sockets, re-run with `sudo` or use `setcap` as shown above.
- If database mappings aren't persisted, check file permissions for `network_detector.db`.

Security & Safety
- Do NOT enable `ACTIVE_PROBING_ENABLED` or `AUTO_BLOCK_ENABLED` on production networks without authorization — these features send network probes and can disrupt services.

Files of interest
- `detector.py` — main detection logic
- `app.py` — Flask dashboard and sniffer launcher
- `config.py` — configuration knobs

Contact
- For changes or tests you'd like automated, tell me which step to run next and I can execute it in the workspace.
