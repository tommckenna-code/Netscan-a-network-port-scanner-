# NetScan — Network Port Scanner

A Python command-line tool that scans a target IP address for open ports
and identifies the services running on them.

Built as a personal cybersecurity project to demonstrate understanding of
TCP/IP networking, socket programming and security fundamentals.

# How to run
open the built in VS terminal and enter the following:
python3 scanner.py

Enter any IP address when prompted. Only use on networks you own.

# What it does

- Scans ports 1–1024 on a target IP
- Identifies open ports and the service likely running on each
- Flags ports commonly associated with security risks (FTP, Telnet, RDP)

# Tech used

- Python 3
- socket library (built-in)

# Legal notice

Only scan IP addresses and networks you own or have explicit permission
to scan. Unauthorised port scanning may be illegal under the Computer
Misuse Act.