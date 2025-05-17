from flask import Flask, jsonify,render_template
from flask_cors import CORS
import scapy.all as scapy

app = Flask(__name__)
CORS(app)  # เปิด CORS

def scan(ip_range="192.168.1.1/24"):
    arp = scapy.ARP(pdst=ip_range)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = scapy.srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

@app.route("/scan")
def scan_devices():
    devices = scan()
    return jsonify(devices)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
