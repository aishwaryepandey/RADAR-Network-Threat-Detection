# RADAR – Real-Time ARP, DNS and DHCP Recognizer

**A Python-based network monitoring and threat detection system designed to identify suspicious ARP, DNS and DHCP activities.**

## 📌 Overview

RADAR (Real-Time ARP, DNS and DHCP Recognizer) is a network security project that monitors network traffic and helps identify potentially suspicious activities involving ARP, DNS and DHCP protocols.

The system uses packet analysis to examine network communication, detect unusual behaviour, generate security alerts and display monitoring information through a web-based dashboard.

## ✨ Key Features

- **ARP Monitoring:** Identifies suspicious ARP activities, including gateway impersonation and ARP mapping changes.
- **DHCP Monitoring:** Observes DHCP traffic and helps identify unauthorised DHCP activity.
- **DNS Monitoring:** Examines DNS responses and identifies responses from untrusted DNS servers.
- **Alert Management:** Generates and records alerts for suspicious network events.
- **Web Dashboard:** Displays monitoring statistics, alert history and system status.
- **Simulation Testing:** Supports predefined scenarios for testing detection functionality.

## 🛠️ Technologies Used

- Python
- Scapy
- Flask
- SQLite
- NumPy
- Pandas
- Scikit-learn
- HTML and CSS

## 📂 Project Structure

```text
RADAR-main/
│
├── network_detector/
│   ├── app.py
│   ├── config.py
│   ├── detector.py
│   ├── run_simulation.py
│   ├── requirements.txt
│   ├── RUNBOOK.md
│   ├── static/
│   └── templates/
│
├── .gitignore
├── LICENSE
└── README.md
```

## ⚙️ Installation and Setup

**1. Clone the repository**

```bash
git clone https://github.com/aishwaryepandey/RADAR-Network-Threat-Detection.git
```

**2. Navigate to the project directory**

```bash
cd RADAR-Network-Threat-Detection/network_detector
```

**3. Create a virtual environment**

```bash
python -m venv venv
```

**4. Activate the environment**

Windows:

```bash
venv\Scripts\activate
```

**5. Install dependencies**

```bash
pip install -r requirements.txt
```

**6. Run the application**

```bash
python app.py
```

Open your browser at:

```text
http://127.0.0.1:5000
```

## 🧪 Simulation

RADAR includes a simulation script for testing predefined network scenarios.

```bash
python run_simulation.py
```

The simulation creates packet objects and passes them to the detection logic without transmitting crafted traffic over a live network.

## ⚠️ Disclaimer

This project is developed for educational and research purposes. Live packet monitoring and network mitigation should only be performed on networks where you have proper authorisation.

## 👩‍💻 Author

**Aishwarye Pandey**

GitHub: [aishwaryepandey](https://github.com/aishwaryepandey)

---

If you find this project interesting, feel free to explore the repository!
