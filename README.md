# PyHT-Python-Hacking-Toolkit

![PyHT Logo](https://github.com/user-attachments/assets/bf1f9276-476e-4aab-964d-1eb864cb3676)

## ⚠️ Legal Notice

This software is designed for:
- **Cybersecurity training**
- **Red team exercises**
- **Security research**
- **Personal lab experiments**

Any use on systems without **explicit permission** from the owner is **unauthorized** and may violate:
- Computer Misuse Acts
- Data Protection Regulations (e.g., GDPR)
- Criminal Codes

Use responsibly. You are solely responsible for your actions.

## Installation 

```bash
sudo apt update && sudo apt upgrade -y
```

```bash
git clone https://github.com/Py-Us3r/PyHT-Python-Hacking-Toolkit.git
cd PyHT-Python-Hacking-Toolkit
```

```bash
python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt
```

```bash
python3 main.py
```

## Port Scanner

[![](https://github.com/user-attachments/assets/92c4eef2-0d6b-4b04-a6d0-fbac57f0f714)](https://youtu.be/cpU3s4uIS5k)

> This tool allows you to scan ports on a target IP address using a user-friendly graphical interface built with customtkinter.

## ARP Scanner 

[![](https://github.com/user-attachments/assets/e9fb5063-9f3d-42f9-b006-8ad39fd7a7ef)](https://youtu.be/qvrkEBCNHxM)

> This module scans the local network using ARP (Address Resolution Protocol) to identify connected devices. It retrieves their IP address, MAC address, and manufacturer information via an external API.

## MAC Changer

[![](https://github.com/user-attachments/assets/e1c4a9ad-2b6b-41eb-bc5a-11266837c6a6)](https://youtu.be/ezkysUO2GRc)

> This module provides a graphical interface to manage the MAC address of network interfaces, allowing you to:

- Check the current MAC address of a selected interface.
- Change the MAC address to a new user-specified value.
- Restore the original MAC address at any time.

## ARP Spoofing / Poisoning

[![](https://github.com/user-attachments/assets/96b397d1-44ac-4511-9e89-61cc0fe9eddc)](https://youtu.be/FkB_YGpAvvU)

> This module allows you to perform ARP Poisoning attacks through a graphical interface, making it easier to test and demonstrate man-in-the-middle (MITM) scenarios in controlled environments.

## ARP Flooding

[![](https://github.com/user-attachments/assets/f24c4e67-1380-4fca-9fea-6701ca586396)](https://youtu.be/WtSOTLevPmw)

> This module allows you to perform ARP flooding attacks through a graphical interface, making it easier to test and demonstrate network disruption and denial-of-service scenarios in controlled environments.It launch of continuous ARP flood packets to overwhelm them, with real-time feedback and control to start or stop the attack safely.

## Sniffer

[![](https://github.com/user-attachments/assets/4cfa1812-30e2-4a9a-9de1-cda2a9fc1126)](https://youtu.be/R4FjesFfFlQ)

> This module provides a graphical packet sniffer that allows you to monitor and analyze network traffic in real time. Designed for use in authorized environments, it supports three distinct sniffing modes:

🔍 Modes:

- Normal Sniffing: Captures and displays a live summary of all network packets on the selected interface.

- DNS Sniffing: Filters and displays only DNS queries (UDP port 53), allowing users to see domain requests made by the system. Common domains like Google or Bing are ignored for clarity.

- HTTP Sniffing: Captures HTTP requests, shows visited URLs, and scans raw packet data for potential credential keywords such as pass, login, or user.

## Command & Control (C2)

[![](https://github.com/user-attachments/assets/a2c4f5e6-553d-4752-ae1e-a3fec2bc09d0)]()

| Category               | Command Name                       | Description |
|------------------------|------------------------------------|-------------|
| 🧬 Persistence          | `Set Persistent`                   | Adds a registry key to auto-start on user login. |
| 🖥️ Remote Access        | `Remote Desktop`                   | Deploys VNC server (UltraVNC) + ngrok tunnel for remote GUI access. |
| 🧪 System Stress Test   | `Powershell Bomb`                  | Infinite PowerShell process spawner. Use only in lab. |
|                        | `Disk Bomb`                        | Fills disk space with hidden 50MB files. Use only in lab. |
| 💻 System Control       | `Reboot System`                    | Reboots the remote machine immediately. |
|                        | `Shutdown System`                  | Shuts down the system immediately. |
|                        | `Set Reboot Persistent`            | Adds script to force reboot on each user login. |
| 🌍 Reconnaissance       | `Get Location`                     | Retrieves IP-based geolocation info. |
|                        | `Get Clipboard`                    | Displays current clipboard content. |
| ⌨️ Keystroke Capture    | `Keylogger`                        | Installs keylogger that emails captured keys. |
| 📸 Visual Interaction   | `Make Screenshot`                  | Takes a screenshot and sends via email. |
|                        | `Show pop-up window`               | Displays a custom message box on the remote system. |
|                        | `Voice Message`                    | Converts text to voice and plays it on the target system. |
| 🔐 Password Recovery    | `Firefox Passwords`                | Extracts saved passwords from Firefox. |
|                        | `Chrome / Edge / etc. Passwords`   | Extracts saved passwords from Chromium-based browsers. |
| 📦 Python Utilities     | `Install Python`                   | Downloads and installs Python 3 silently if not available. |
| 🔒 File Encryption      | `Encrypt File(s)`                  | Encrypts specified files using Python script and fixed key. |
|                        | `Encrypt All Files`                | Recursively encrypts user documents (txt, docx, pdf, etc.). |
|                        | `Encrypt All Files with Alert`     | Same as above + warning pop-up and voice message. |
|                        | `List Encrypted File(s)`           | Displays a log of previously encrypted files. |
|                        | `Decrypt File(s)`                  | Decrypts previously encrypted files using the same key. |


