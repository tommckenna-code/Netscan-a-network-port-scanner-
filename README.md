# NetScan – Network Port Scanner

A Python command-line tool that scans a target IP address for open ports and identifies the services running on them. Built as a personal cyber security project to demonstrate TCP/IP networking, socket programming and security fundamentals.

<img width="1179" height="446" alt="image" src="https://github.com/user-attachments/assets/7f7096da-c9f0-48c4-bcf2-61d780c1f59f" />

## What it does
- Scans ports 1–1024 on a target IP
- Identifies open ports and the service likely running on each
- Flags ports commonly associated with security risks (FTP, Telnet, RDP)

## In progress
- **Multi-threaded scanning:** scanning many ports at once to cut scan time
- **Flask dashboard:** a web view of scan results with exportable reports

## How to run
    python3 scanner.py

Enter the IP of a device you own when prompted, e.g. your home router.

## Tech used
- Python 3
- socket library (built-in)

## Legal notice
Only scan networks and devices you own or have explicit permission to test. Unauthorised port scanning may be illegal under the Computer Misuse Act 1990.
