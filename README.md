# 🔑 Keylogger with Encrypted Data Exfiltration (PoC)

## 📌 Overview
This is a **proof-of-concept keylogger tool** built for **educational and authorized security research**.  
It captures keystrokes, encrypts the data, stores logs locally, and simulates exfiltration to a remote server.  
The purpose of this tool is to demonstrate potential attack techniques so defenders can design **better detection and prevention strategies**.

⚠️ **Disclaimer:** This project is for **learning and authorized penetration testing only**.  
Using it on systems without explicit written permission is **illegal**.

---

## ✨ Features
- 🖊️ Capture keystrokes in real-time using `pynput`.  
- 🔐 Encrypt captured data with `cryptography.fernet`.  
- 📂 Store logs locally with timestamped entries.  
- 🌐 Simulate exfiltration by sending encrypted logs to a local Flask server.  
- 🛑 Built-in **kill switch** to stop logging safely.  
- 🔄 Demo of startup persistence (educational only).  
