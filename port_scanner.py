import nmap

def run_port_scan(ip):
    """Scans a specific IP for open ports and retrieves detailed service info."""
    try:
        nm = nmap.PortScanner()
        print(f"Scanning {ip} for open ports...")  # Debugging

        nm.scan(ip, arguments="-p 1-65535 --open -sV")  # Scan all open ports with service detection
        
        # Debugging: Print the raw scan output
        print(f"Nmap raw scan output for {ip}:\n", nm.csv())

        open_ports = []
        if ip in nm.all_hosts():
            for port in nm[ip]["tcp"]:
                service_info = nm[ip]["tcp"][port]
                open_ports.append({
                    "port": port,
                    "state": service_info["state"],
                    "service": service_info.get("name", "Unknown"),
                    "product": service_info.get("product", "Unknown"),
                    "version": service_info.get("version", "Unknown"),
                    "extra_info": service_info.get("extrainfo", "Unknown")
                })

        if not open_ports:
            print(f"No open ports found on {ip}")

        return {"ip": ip, "open_ports": open_ports}

    except Exception as e:
        print(f"Error scanning ports for {ip}: {e}")
        return {"error": str(e)}
