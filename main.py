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
import platform
import json
import ipaddress

# Load the manuf parser with the specified file
manuf_file_path = os.path.join(os.getcwd(), 'manuf.txt')
p = manuf.MacParser(manuf_file_path)

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
    """Retrieve network CIDR based on default gateway."""
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    iface = gateways['default'][netifaces.AF_INET][1]
    
    addr_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    network = ipaddress.IPv4Network(f"{addr_info['addr']}/{addr_info['netmask']}", strict=False)
    
    return str(network)


def get_devices_on_network(ip_range):
    """Send ARP requests to find active devices on the network."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=5, verbose=0, retry=2)[0]

    devices = []
    for _, received in result:
        mac = received.hwsrc
        manufacturer = p.get_manuf(mac) or "Unknown"
        name = get_device_name(received.psrc, manufacturer) or retry_get_device_name(received.psrc)

        devices.append({
            "ip": received.psrc,
            "mac": mac,
            "name": name if name != "Unknown" else None,
            "manufacturer": manufacturer
        })

    return devices

def get_device_name(ip, manufacturer):
    """Retrieve device hostname using multiple methods."""
    methods = [
        lambda: socket.gethostbyaddr(ip)[0],
        lambda: nmap_lookup(ip),
        lambda: ping_lookup(ip),
        lambda: netbios_lookup(ip),
        lambda: dns_ptr_lookup(ip)
    ]

    for method in methods:
        try:
            hostname = method()
            if hostname and hostname != "Unknown":
                return hostname
        except Exception as e:
            continue  # Silent fail, move to the next method

    return heuristic_lookup(manufacturer)

def nmap_lookup(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sP')
    return nm[ip].hostname() if ip in nm.all_hosts() else None

def ping_lookup(ip):
    cmd = ["ping", "-a", "-n", "1", ip] if platform.system().lower() == "windows" else ["ping", "-c", "1", "-W", "1", ip]
    result = subprocess.run(cmd, capture_output=True, text=True).stdout
    if "[" in result:
        return result.split("[")[1].split("]")[0]
    elif "(" in result:
        return result.split("(")[1].split(")")[0]
    return None

def netbios_lookup(ip):
    if platform.system().lower() == "windows":
        result = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True).stdout
        for line in result.split("\n"):
            if "<20>" in line and "UNIQUE" in line:
                return line.split()[0].strip()
    else:
        result = subprocess.run(["avahi-resolve", "-a", ip], capture_output=True, text=True).stdout
        return result.split("\t")[-1].strip() if result else None

def dns_ptr_lookup(ip):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [netifaces.gateways()['default'][netifaces.AF_INET][0]]
    reversed_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    answers = resolver.resolve(reversed_ip, "PTR")
    return str(answers[0]) if answers else None

def heuristic_lookup(manufacturer):
    """Guess device type based on manufacturer."""
    lower_manufacturer = manufacturer.lower()
    if "apple" in lower_manufacturer:
        return "iPhone"
    if any(x in lower_manufacturer for x in ["samsung", "huawei", "xiaomi", "google"]):
        return "Android"
    return "Unknown"



def get_mdns_devices():
    """Discover devices using mDNS."""
    zeroconf = Zeroconf()
    listener = MyListener()
    services = ["_services._dns-sd._udp.local.", "_http._tcp.local.", "_device-info._tcp.local."]

    for service in services:
        ServiceBrowser(zeroconf, service, listener)

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
    mdns_map = {device["ip"]: device["name"] for device in mdns_devices}
    upnp_map = {device["ip"]: device["name"] for device in upnp_devices}

    device_list = []
    
    for idx, device in enumerate(devices, start=1):
        name = device["name"]
        if name == "Unknown":
            if device["ip"] in mdns_map:
                name = mdns_map[device["ip"]]
            elif device["ip"] in upnp_map:
                name = upnp_map[device["ip"]]

        manufacturer = device.get("manufacturer", "Unknown")
        
        # Store structured data instead of printing a table
        device_list.append({
            "id": str(idx),
            "name": name,
            "mac": device["mac"],
            "ip": device["ip"],
            "manufacturer": manufacturer
        })

    # Print JSON instead of a table (so Flask can read it)
    print(json.dumps(device_list))


if __name__ == "__main__":
    # Automatically determine the network range
    network_range = get_network_range()

    devices = get_devices_on_network(network_range)
    mdns_devices = get_mdns_devices()
    upnp_devices = get_upnp_devices()
    print_devices(devices, mdns_devices, upnp_devices)
