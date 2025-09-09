<img width="789" height="579" alt="image" src="https://github.com/user-attachments/assets/0962b7b5-cdb1-4e2e-9ef7-1a760731e332" />

# 🔍 EasyNmap - Simple Nmap Wrapper

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%2C%20Linux%2C%20macOS-lightgrey)

**EasyNmap** is a simple command-line interface that makes Nmap easier to use for beginners. It provides a menu-driven approach to common Nmap scans without needing to remember complex command-line options.

## ✨ What It Does

- Provides a simple menu for common Nmap scan types
- Displays results in a clean, formatted way
- Offers basic color output for better readability
- Allows saving results to text files
- Works on Windows, Linux, and macOS

## 📋 Available Scan Types

1. **Fast Scan** (`-F`) - Quick scan of common ports
2. **Stealth Scan** (`-sS`) - SYN scan (requires root/admin)
3. **Version Scan** (`-sV`) - Service version detection
4. **OS Detection** (`-O`) - Operating system detection
5. **Aggressive Scan** (`-A`) - Combination scan
6. **UDP Scan** (`-sU`) - UDP port scanning
7. **Custom Port Scan** (`-p`) - Scan specific ports

## 🛠️ Requirements

- Python 3.6 or higher
- Nmap installed on your system
- Required Python libraries:
  - `python-nmap`
  - `os`
  - `pystyle`

### Installation

```bash
# Install Nmap first
# On Ubuntu/Debian:
sudo apt-get install nmap

# On Windows:
# Download from https://nmap.org/download.html

# Install Python dependencies
pip install -r requirements.txt
