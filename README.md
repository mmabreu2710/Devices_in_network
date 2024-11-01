# Devices in Network Project

## Prerequisites
To get started, make sure you have the following installed:

1. **Microsoft Visual C++ Build Tools**  
   Ensure that the *Desktop development with C++* workload is selected during installation.

2. **Python Packages**  
   Install the required Python packages by running the following commands in your terminal:

   """
   pip install netifaces
   pip install scapy prettytable
   pip install scapy prettytable netifaces python-nmap smbprotocol zeroconf
   pip install scapy prettytable netifaces python-nmap zeroconf miniupnpc
   pip install scapy prettytable netifaces python-nmap zeroconf upnpclient
   """

## Updating the Manufacturer File
The `manuf.txt` file is used to identify manufacturers of network devices by their MAC addresses. To keep this file up-to-date with the latest manufacturer information:

- Visit the [Wireshark OUI lookup page](https://www.wireshark.org/tools/oui-lookup.html) or similar websites.
- Download the latest version and replace your `manuf.txt` file with the updated one.

## Running the Project
To run the project, execute the following command in your terminal:

"""
python main.py
"""

## Device Information Displayed
Each device on the network is identified and displayed with the following details:

- **Name**: Device name
- **IP Address**: Device IP address
- **MAC Address**: Device MAC address
- **Manufacturer**: Device manufacturer, retrieved from `manuf.txt`

---

This setup will help ensure that your network device project functions optimally, keeping your dependencies organized and up-to-date.
