import json
import subprocess
from flask import Flask, render_template, jsonify, request
from port_scanner import run_port_scan  # Import the function from port_scanner.py

app = Flask(__name__)

def run_network_scan():
    """Runs the network scanning script and returns JSON results."""
    try:
        print("Running network scan...")

        # Run main.py and capture output
        result = subprocess.run(
            ["sudo", "python3", "main.py"], capture_output=True, text=True
        )

        print("Raw Scan Output:\n", result.stdout)  # Debugging

        # Extract the last valid JSON object
        json_output = result.stdout.strip().split("\n")[-1]

        devices = json.loads(json_output)  # Parse JSON
        print("Parsed Devices:", devices)

        return devices

    except json.JSONDecodeError:
        print("Error: Unable to parse JSON from scan output")
        return {"error": "Failed to parse network scan output"}
    except Exception as e:
        print("Error in scanning:", e)
        return {"error": str(e)}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan")
def scan():
    """API endpoint to run the network scan."""
    return jsonify(run_network_scan())

@app.route("/scan/<ip>")
def scan_ip(ip):
    """API endpoint to scan a specific IP for open ports."""
    return render_template("port_scan.html", ip=ip)

@app.route("/api/scan/<ip>")
def api_scan_ip(ip):
    """API endpoint for port scanning results."""
    return jsonify(run_port_scan(ip))  # Call function from port_scanner.py

if __name__ == "__main__":
    app.run(debug=True)
