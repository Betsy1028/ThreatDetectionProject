Threat Detection Project

This project demonstrates a simple threat detection and reporting system using Python.  
It parses event logs, identifies suspicious users, commands, and IP addresses, and generates a PDF report with charts.

Features

- Detects suspicious activity based on:
  - Users: `admin1`, `testuser`, `unknown`
  - Commands: `powershell.exe -nop`, `wmic`, `schtasks /create`
  - IPs: `192.168.100.100`, `10.10.10.200`
- Generates **alerts** and **charts** embedded in a PDF report
- Easy to extend with new rules or logs
- Sample logs included for testing

Installation

1. Install Python 3.13+ (or latest)
2. Install required packages:
```bash
python -m pip install fpdf matplotlib
