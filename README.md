# **Network Scanner Web Application**

## **📌 Project Overview**
This is a **web-based network scanner** built with **Flask** that detects devices on a network, retrieves their **IP addresses, MAC addresses, manufacturers, and hostnames**, and allows **detailed port scanning** of individual devices.

### **🔹 Features**
✅ **Scan the local network** to detect connected devices.  
✅ **Retrieve device details** (MAC address, manufacturer, hostname).  
✅ **Clickable rows** redirect to a new page for **port scanning**.  
✅ **Perform deep port scans** on a selected device.  
✅ **Display service details** for each open port (service name, version, extra info).  
✅ **Runs entirely in a web browser** with a simple **Flask API backend**.

---

## **🛠️ Installation**
### **🔹 1. Clone the Repository**
```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```

### **🔹 2. Set Up a Virtual Environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate    # On Windows
```

### **🔹 3. Install Dependencies**
```bash
pip install -r requirements.txt
```

### **🔹 4. Install System Dependencies (Linux/macOS)**
Ensure that `nmap` is installed on your system:
```bash
sudo apt install nmap  # Debian/Ubuntu
brew install nmap      # macOS
```

---

## **🚀 Running the Application**
### **🔹 Start the Flask Web App**
```bash
sudo venv/bin/python3 app.py
```

Open **http://127.0.0.1:5000** in your browser.

### **🔹 How It Works**
1. Click **"Scan Network"** to discover devices.
2. Click on a device row to scan its open ports.
3. View **detailed service information** for each open port.

---

## **🖥️ File Structure**
```bash
network-scanner/
│── app.py          # Flask API backend
│── main.py         # Network scanning logic (device discovery)
│── port_scanner.py # Port scanning logic
│── templates/
│   ├── index.html       # Main UI (network scan results)
│   ├── port_scan.html   # Detailed port scan results
│── static/
│── requirements.txt     # Python dependencies
│── README.md            # Project documentation
```

---

## **🌐 API Endpoints**
### **🔹 Network Scan**
```
GET /scan
```
- Scans the local network and returns a list of detected devices.

### **🔹 Port Scan for a Specific IP**
```
GET /api/scan/<ip>
```
- Scans the specified IP for open ports and returns detailed service information.

---

## **💡 Example Usage**
### **🔹 Network Scan Response**
```json
[
    {
        "id": "1",
        "name": "TL-WPA4220.Home",
        "mac": "00:31:92:5e:01:36",
        "ip": "192.168.1.112",
        "manufacturer": "TPLink"
    },
    {
        "id": "2",
        "name": "meo.Home",
        "mac": "00:06:91:3d:a0:6f",
        "ip": "192.168.1.254",
        "manufacturer": "PTInovacao"
    }
]
```

### **🔹 Port Scan Response**
```json
{
    "ip": "192.168.1.112",
    "open_ports": [
        {
            "port": 22,
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.2p1",
            "extra_info": "Ubuntu"
        },
        {
            "port": 80,
            "state": "open",
            "service": "http",
            "product": "Apache",
            "version": "2.4.41",
            "extra_info": ""
        }
    ]
}
```

---

## **🛠️ Troubleshooting**
### **🔹 No Open Ports Found?**
1. Run **Nmap manually** to confirm ports are open:
   ```bash
   sudo nmap -p 1-65535 --open -sV 192.168.1.112
   ```
2. Try using **`-Pn`** (some devices block ping requests):
   ```bash
   sudo nmap -p 1-65535 -sV -Pn 192.168.1.112
   ```
3. Check if the **device has running services** (SSH, web, etc.).
4. Disable **firewalls** temporarily:
   ```bash
   sudo ufw disable  # Linux (UFW firewall)
   netsh advfirewall set allprofiles state off  # Windows
   ```

### **🔹 `ModuleNotFoundError: No module named 'nmap'`**
Run:
```bash
source venv/bin/activate  # Activate virtual environment
pip install python-nmap
```
If using `sudo`, install inside `venv`:
```bash
sudo venv/bin/python3 -m pip install python-nmap
```

### **🔹 `nmap` Not Installed?**
Check if `nmap` is installed:
```bash
which nmap
```
If missing, install:
```bash
sudo apt install nmap  # Debian/Ubuntu
brew install nmap      # macOS
```


## **💡 Future Improvements**
- 📊 **Graphical visualization** of scanned results.
- 🌎 **Remote scanning** (scan external networks via VPN/Tunnel).
- 📌 **More detailed device fingerprinting** using passive techniques.
- 🔐 **Authentication system** to restrict access.

---

🚀 **Now you're ready to scan your network like a pro!** 🔥

