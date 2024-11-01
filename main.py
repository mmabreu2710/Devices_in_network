from scapy.all import ARP, Ether, srp
from prettytable import PrettyTable
import socket
import netifaces
import nmap
import subprocess
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
import upnpclient
import dns.resolver
import os
from manuf import manuf

# Load the manuf parser with the specified file
manuf_file_path = os.path.join(os.getcwd(), 'manuf.txt')
p = manuf.MacParser(manuf_file_path)

# Debugging: Check a few example MAC addresses
example_macs = ["44:cb:8b:61:cc:8e", "00:31:92:5e:01:36", "68:3e:26:73:e1:c8"]
print("Example MAC address lookups:")
for mac in example_macs:
    manufacturer = p.get_manuf(mac)
    print(f"{mac}: {manufacturer}")

class MyListener(ServiceListener):
    def __init__(self):
        self.devices = []

    def remove_service(self, zeroconf, type, name):
        pass

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            self.devices.append({
                "name": info.name,
                "ip": socket.inet_ntoa(info.addresses[0])
            })

def get_network_range():
    # Get the default gateway
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    
    # Get the network interface for the default gateway
    iface = gateways['default'][netifaces.AF_INET][1]
    
    # Get the IP address and subnet mask
    addr_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    ip_address = addr_info['addr']
    subnet_mask = addr_info['netmask']
    
    # Calculate the network address
    ip_parts = list(map(int, ip_address.split('.')))
    mask_parts = list(map(int, subnet_mask.split('.')))
    network_parts = [ip & mask for ip, mask in zip(ip_parts, mask_parts)]
    network_address = ".".join(map(str, network_parts))
    
    # Calculate the network range
    network_range = f"{network_address}/{sum(bin(mask).count('1') for mask in mask_parts)}"
    
    return network_range

def get_devices_on_network(ip_range):
    # Create ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and get the response
    result = srp(packet, timeout=5, verbose=0, retry=2)[0]

    devices = []
    for sent, received in result:
        mac = received.hwsrc
        manufacturer = p.get_manuf(mac) or "Unknown"
        name = get_device_name(received.psrc, manufacturer)
        if name == "Unknown":
            name = retry_get_device_name(received.psrc)
        if name == "Unknown" and manufacturer == "Unknown":
            print(f"Unknown device found: IP {received.psrc}, MAC {mac}")
        device = {
            "ip": received.psrc,
            "mac": mac,
            "name": name,
            "manufacturer": manufacturer
        }
        devices.append(device)

    return devices

def get_device_name(ip, manufacturer):
    # Try to get the hostname using socket
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"Socket hostname for {ip}: {hostname}")
        return hostname
    except socket.herror:
        pass

    # Try to get the hostname using nmap
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sP')
        if ip in nm.all_hosts():
            hostname = nm[ip].hostname()
            print(f"Nmap hostname for {ip}: {hostname}")
            return hostname
    except Exception as e:
        print(f"Error using nmap for IP {ip}: {e}")

    # Try to get the hostname using ping
    try:
        result = subprocess.check_output(["ping", "-a", "-n", "1", ip], universal_newlines=True)
        for line in result.split('\n'):
            if "Pinging" in line and "[" in line:
                start = line.find("[") + 1
                end = line.find("]")
                hostname = line[start:end]
                print(f"Ping hostname for {ip}: {hostname}")
                return hostname
    except subprocess.CalledProcessError:
        pass

    # Try to get the hostname using nbtstat
    try:
        result = subprocess.check_output(["nbtstat", "-A", ip], universal_newlines=True)
        for line in result.split('\n'):
            if "<20>" in line and "UNIQUE" in line:
                hostname = line.split()[0].strip()
                print(f"NBTSTAT hostname for {ip}: {hostname}")
                return hostname
    except subprocess.CalledProcessError as e:
        print(f"Error using nbtstat for IP {ip}: {e}")

    # Try to get the hostname using DNS PTR lookup
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [netifaces.gateways()['default'][netifaces.AF_INET][0]]
        reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
        answers = resolver.resolve(reversed_ip, 'PTR')
        for rdata in answers:
            hostname = str(rdata)
            print(f"DNS PTR hostname for {ip}: {hostname}")
            if hostname.startswith("android-") or hostname.startswith("iphone-"):
                return hostname
    except Exception as e:
        print(f"Error using DNS PTR for IP {ip}: {e}")
    
    # Heuristic based on manufacturer
    if "apple" in manufacturer.lower():
        return "iPhone"
    elif "samsung" in manufacturer.lower() or "huawei" in manufacturer.lower() or "xiaomi" in manufacturer.lower() or "google" in manufacturer.lower():
        return "Android"

    return "Unknown"

def retry_get_device_name(ip):
    # Retry all methods for name resolution
    name = get_device_name(ip, "")
    if name == "Unknown":
        try:
            result = subprocess.check_output(["ping", "-a", "-n", "3", ip], universal_newlines=True)
            for line in result.split('\n'):
                if "Pinging" in line and "[" in line:
                    start = line.find("[") + 1
                    end = line.find("]")
                    hostname = line[start:end]
                    print(f"Ping retry hostname for {ip}: {hostname}")
                    return hostname
        except subprocess.CalledProcessError:
            pass

        try:
            result = subprocess.check_output(["nbtstat", "-A", ip], universal_newlines=True)
            for line in result.split('\n'):
                if "<20>" in line and "UNIQUE" in line:
                    hostname = line.split()[0].strip()
                    print(f"NBTSTAT retry hostname for {ip}: {hostname}")
                    return hostname
        except subprocess.CalledProcessError as e:
            print(f"Error using nbtstat for IP {ip}: {e}")

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [netifaces.gateways()['default'][netifaces.AF_INET][0]]
            reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
            answers = resolver.resolve(reversed_ip, 'PTR')
            for rdata in answers:
                hostname = str(rdata)
                print(f"DNS PTR retry hostname for {ip}: {hostname}")
                return hostname
        except Exception as e:
            print(f"Error using DNS PTR for IP {ip}: {e}")

    return name

def get_mdns_devices():
    zeroconf = Zeroconf()
    listener = MyListener()
    ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", listener)
    ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    ServiceBrowser(zeroconf, "_device-info._tcp.local.", listener)
    zeroconf.close()
    return listener.devices

def get_upnp_devices():
    result = []
    try:
        devices = upnpclient.discover()
        for device in devices:
            result.append({
                "name": device.friendly_name,
                "ip": device.location.split('/')[2].split(':')[0]
            })
    except Exception as e:
        print(f"Error retrieving UPnP devices: {e}")
    return result

def print_devices(devices, mdns_devices, upnp_devices):
    table = PrettyTable()
    table.field_names = ["ID", "Name", "MAC Address", "IP Address", "Manufacturer"]

    mdns_map = {device["ip"]: device["name"] for device in mdns_devices}
    upnp_map = {device["ip"]: device["name"] for device in upnp_devices}
    
    for idx, device in enumerate(devices, start=1):
        name = device["name"]
        if name == "Unknown":
            if device["ip"] in mdns_map:
                name = mdns_map[device["ip"]]
            elif device["ip"] in upnp_map:
                name = upnp_map[device["ip"]]
        manufacturer = device.get("manufacturer", "Unknown")
        table.add_row([idx, name, device["mac"], device["ip"], manufacturer])

    print(table)

if __name__ == "__main__":
    # Automatically determine the network range
    network_range = get_network_range()

    print(f"Scanning the network {network_range}...")
    devices = get_devices_on_network(network_range)
    mdns_devices = get_mdns_devices()
    upnp_devices = get_upnp_devices()
    print_devices(devices, mdns_devices, upnp_devices)
