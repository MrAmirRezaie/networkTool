import socket
import argparse
import logging
import json
import csv
import time
import random
import asyncio
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, UDP, sr1, ICMP, conf, sr, ARP, IPv6, ICMPv6EchoRequest, traceroute
from scapy.error import Scapy_Exception
from ipaddress import ip_network, ip_address
from datetime import datetime
import geoip2.database
import matplotlib.pyplot as plt
import plotly.express as px
from fpdf import FPDF
from cryptography.fernet import Fernet
import stem.process
from stem.util import term
import schedule
import gettext
import os
import ssl
import subprocess
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import numpy as np
import pymodbus.client as ModbusClient
import paho.mqtt.client as mqtt
import aiocoap as coap
import smtplib
from email.mime.text import MIMEText
import folium
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import hmac
import base64
from typing import List, Dict, Any, Optional
import tarfile

# Scapy settings to suppress unnecessary messages
conf.verb = 0

# Logging settings
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Path to GeoLite2 database (download from https://dev.maxmind.com/geoip/geoip2/geolite2/)
GEOIP_DATABASE_PATH = 'GeoLite2-City.mmdb'

# URL to download GeoLite2 database (you need to sign up for a free license key from MaxMind)
GEOIP_DOWNLOAD_URL = 'https://download.maxmind.com/app/geoip_download'
LICENSE_KEY = 'your_license_key_here'  # Replace with your actual license key

# List of common ports
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080]

# List of vulnerable ports
VULNERABLE_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5900, 8080]

# List of management ports
MANAGEMENT_PORTS = [3389, 5900, 8080, 8443]

# List of IoT common ports
IOT_PORTS = [1883, 5683, 8080, 8883, 5684]  # MQTT, CoAP, HTTP, HTTPS, CoAPs

# Encryption key (for encrypting data)
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Language settings (support for multilingual)
LOCALE_DIR = os.path.join(os.path.dirname(__file__), 'locales')
gettext.bindtextdomain('messages', LOCALE_DIR)
gettext.textdomain('messages')
_ = gettext.gettext

# Local threat intelligence: List of known malicious IPs
MALICIOUS_IPS = [
    "192.168.1.100",  # Example malicious IP
    "10.0.0.1",  # Example malicious IP
]

# Email settings for sending alerts
EMAIL_SETTINGS = {
    'smtp_server': 'smtp.example.com',
    'smtp_port': 587,
    'email_address': 'your_email@example.com',
    'email_password': 'your_email_password',
    'recipient_email': 'recipient@example.com'
}

# Webhook settings for sending alerts (e.g., Slack)
WEBHOOK_URL = 'https://hooks.slack.com/services/your/webhook/url'


# Function to download GeoLite2 database
def download_geolite2_database():
    # Check if the database already exists
    if os.path.exists(GEOIP_DATABASE_PATH):
        logging.info("GeoLite2 database already exists.")
        return

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(GEOIP_DATABASE_PATH), exist_ok=True)

    # Download the GeoLite2 database
    try:
        logging.info("Downloading GeoLite2 database...")
        response = requests.get(
            f"{GEOIP_DOWNLOAD_URL}?edition_id=GeoLite2-City&license_key={LICENSE_KEY}&suffix=tar.gz", stream=True)
        response.raise_for_status()

        # Save the downloaded file
        tar_path = 'GeoLite2-City.tar.gz'
        with open(tar_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        # Extract the tar.gz file
        with tarfile.open(tar_path, 'r:gz') as tar:
            tar.extractall()

        # Find the .mmdb file in the extracted directory
        for root, dirs, files in os.walk('.'):
            for file in files:
                if file.endswith('.mmdb'):
                    mmdb_path = os.path.join(root, file)
                    os.rename(mmdb_path, GEOIP_DATABASE_PATH)
                    break

        # Clean up the tar.gz file and extracted directory
        os.remove(tar_path)
        for root, dirs, files in os.walk('.'):
            for dir in dirs:
                if dir.startswith('GeoLite2-City_'):
                    os.rmdir(os.path.join(root, dir))

        logging.info("GeoLite2 database downloaded and extracted successfully.")
    except Exception as e:
        logging.error(f"Error downloading GeoLite2 database: {e}")


# Call the function to download the database
download_geolite2_database()


# Function to get geographical location of an IP
def get_geolocation(ip: str) -> Optional[Dict[str, Any]]:
    try:
        with geoip2.database.Reader(GEOIP_DATABASE_PATH) as reader:
            response = reader.city(ip)
            return {
                "city": response.city.name,
                "country": response.country.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }
    except Exception as e:
        logging.error(f"Error getting geolocation for IP {ip}: {e}")
    return None


# Function to create a map with IP locations
def create_ip_map(results: List[Dict[str, Any]]) -> None:
    try:
        # Create a map centered at the first IP's location
        first_ip = results[0]["ip"]
        first_location = get_geolocation(first_ip)
        if first_location:
            ip_map = folium.Map(location=[first_location["latitude"], first_location["longitude"]], zoom_start=10)
        else:
            ip_map = folium.Map(location=[0, 0], zoom_start=2)

        # Add markers for each IP
        for result in results:
            location = get_geolocation(result["ip"])
            if location:
                folium.Marker(
                    [location["latitude"], location["longitude"]],
                    popup=f"IP: {result['ip']}, Port: {result['port']}, Status: {result['status']}",
                ).add_to(ip_map)

        # Save the map to an HTML file
        ip_map.save("ip_locations_map.html")
        logging.info("IP location map saved to ip_locations_map.html")
    except Exception as e:
        logging.error(f"Error creating IP location map: {e}")


# Function to scan TCP port with service and OS detection
def scan_tcp_port(ip: str, port: int, timeout: int = 1, version_detection: bool = False, os_detection: bool = False) -> \
tuple[int, str, str]:
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "unknown"
            if version_detection:
                # Attempt to get service version
                try:
                    sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    service = f"{service} ({banner.splitlines()[0]})"
                except:
                    pass
            if os_detection:
                # Attempt to get OS information
                try:
                    sock.send(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                    os_info = sock.recv(1024).decode('utf-8', errors='ignore')
                    service = f"{service} (OS: {os_info})"
                except:
                    pass
            return port, "open", service
        sock.close()
    except Exception as e:
        logging.error(f"Error scanning TCP port {port} on {ip}: {e}")
    return port, "closed", "unknown"


# Function to scan UDP port
def scan_udp_port(ip: str, port: int, timeout: int = 1) -> tuple[int, str, str]:
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            return port, "open", "unknown"
        except socket.timeout:
            return port, "open|filtered", "unknown"
        except Exception as e:
            return port, "closed", "unknown"
    except Exception as e:
        logging.error(f"Error scanning UDP port {port} on {ip}: {e}")
    return port, "closed", "unknown"


# Function to scan SYN port
def scan_syn_port(ip: str, port: int, timeout: int = 1) -> tuple[int, str, str]:
    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                return port, "open", "unknown"
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                return port, "closed", "unknown"
        return port, "filtered", "unknown"
    except Exception as e:
        logging.error(f"Error scanning SYN port {port} on {ip}: {e}")
    return port, "closed", "unknown"


# Function to scan TCP port using async
async def async_scan_tcp_port(ip: str, port: int, timeout: int = 1, version_detection: bool = False,
                              os_detection: bool = False) -> tuple[int, str, str]:
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            await asyncio.wait_for(asyncio.get_event_loop().sock_connect(sock, (ip, port)), timeout)
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "unknown"
            if version_detection:
                # Attempt to get service version
                try:
                    sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    service = f"{service} ({banner.splitlines()[0]})"
                except:
                    pass
            if os_detection:
                # Attempt to get OS information
                try:
                    sock.send(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                    os_info = sock.recv(1024).decode('utf-8', errors='ignore')
                    service = f"{service} (OS: {os_info})"
                except:
                    pass
            return port, "open", service
        except asyncio.TimeoutError:
            return port, "closed", "unknown"
        finally:
            sock.close()
    except Exception as e:
        logging.error(f"Error scanning TCP port {port} on {ip}: {e}")
    return port, "closed", "unknown"


# Function to rate limit scanning
def rate_limit(rate: int) -> None:
    if rate > 0:
        time.sleep(1 / rate)


# Function to start Tor
def start_tor() -> Optional[stem.process.LaunchedTor]:
    try:
        tor_process = stem.process.launch_tor_with_config(
            config={
                'SocksPort': '9050',
                'ControlPort': '9051',
            },
            init_msg_handler=lambda line: print(term.format(line, term.Color.BLUE)),
        )
        return tor_process
    except Exception as e:
        logging.error(f"Error starting Tor: {e}")
    return None


# Function to encrypt data
def encrypt_data(data: str) -> Optional[bytes]:
    try:
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data
    except Exception as e:
        logging.error(f"Error encrypting data: {e}")
    return None


# Function to decrypt data
def decrypt_data(encrypted_data: bytes) -> Optional[str]:
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        return decrypted_data
    except Exception as e:
        logging.error(f"Error decrypting data: {e}")
    return None


# Function to load configuration from a file
def load_config(config_file: str) -> Optional[Dict[str, Any]]:
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        logging.error(f"Error loading config file: {e}")
    return None


# Function to save configuration to a file
def save_config(config: Dict[str, Any], config_file: str) -> None:
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4)
        logging.info(f"Config saved to {config_file}")
    except Exception as e:
        logging.error(f"Error saving config file: {e}")


# Function to analyze data
def analyze_data(results: List[Dict[str, Any]]) -> Dict[str, int]:
    analysis = {
        "total_ports_scanned": len(results),
        "open_ports": len([r for r in results if r["status"] == "open"]),
        "closed_ports": len([r for r in results if r["status"] == "closed"]),
        "filtered_ports": len([r for r in results if r["status"] == "filtered"]),
        "common_ports_open": len([r for r in results if r["status"] == "open" and r["port"] in COMMON_PORTS]),
    }
    return analysis


# Function to save results in different formats
def save_results(results: List[Dict[str, Any]], output_file: str, analysis: Optional[Dict[str, int]] = None) -> None:
    try:
        if output_file.endswith('.json'):
            with open(output_file, 'w') as f:
                json.dump({"results": results, "analysis": analysis}, f, indent=4)
        elif output_file.endswith('.csv'):
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        elif output_file.endswith('.xml'):
            root = ET.Element("scan_results")
            for result in results:
                entry = ET.SubElement(root, "entry")
                for key, value in result.items():
                    ET.SubElement(entry, key).text = str(value)
            tree = ET.ElementTree(root)
            tree.write(output_file)
        elif output_file.endswith('.html'):
            with open(output_file, 'w') as f:
                f.write("<html><body><h1>Scan Results</h1><table border='1'>")
                f.write("<tr><th>Port</th><th>Status</th><th>Service</th><th>IP</th></tr>")
                for result in results:
                    f.write(
                        f"<tr><td>{result['port']}</td><td>{result['status']}</td><td>{result['service']}</td><td>{result['ip']}</td></tr>")
                f.write("</table></body></html>")
        elif output_file.endswith('.pdf'):
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt="Scan Results", ln=True, align='C')
            for result in results:
                pdf.cell(200, 10,
                         txt=f"Port: {result['port']}, Status: {result['status']}, Service: {result['service']}, IP: {result['ip']}",
                         ln=True)
            pdf.output(output_file)
        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving results to {output_file}: {e}")


# Function to create charts
def create_charts(results: List[Dict[str, Any]], output_file: str) -> None:
    try:
        # Chart for open, closed, and filtered ports
        status_counts = {
            "open": len([r for r in results if r["status"] == "open"]),
            "closed": len([r for r in results if r["status"] == "closed"]),
            "filtered": len([r for r in results if r["status"] == "filtered"]),
        }
        plt.bar(status_counts.keys(), status_counts.values())
        plt.title("Port Status Distribution")
        plt.xlabel("Status")
        plt.ylabel("Count")
        plt.savefig(f"{output_file}_status_chart.png")
        plt.close()

        # Interactive chart with Plotly
        df = px.data.tips()
        fig = px.bar(x=list(status_counts.keys()), y=list(status_counts.values()), labels={'x': 'Status', 'y': 'Count'},
                     title="Port Status Distribution")
        fig.write_html(f"{output_file}_status_chart.html")
    except Exception as e:
        logging.error(f"Error creating charts: {e}")


# Function to perform scheduled scans
def scheduled_scan(config_file: str) -> None:
    config = load_config(config_file)
    if config:
        logging.info(_("Starting scheduled scan with config: {}").format(config))
        # Perform scan based on config
        targets = config.get("targets", [])
        ports = config.get("ports", "1-1024")
        scan_type = config.get("type", "tcp")
        timeout = config.get("timeout", 1)
        max_threads = config.get("max_threads", 100)
        rate_limit_value = config.get("rate_limit", 0)

        # Convert port range to list
        if isinstance(ports, str):
            if '-' in ports:
                start_port, end_port = map(int, ports.split('-'))
                ports = list(range(start_port, end_port + 1))
            else:
                ports = list(map(int, ports.split(',')))

        # Perform the scan
        all_results = []
        for target in targets:
            logging.info(_("Scanning target: {}").format(target))
            if rate_limit_value > 0:
                rate_limit(rate_limit_value)
            results = full_scan(target, ports, scan_type, timeout, max_threads)
            all_results.extend(results)

        # Save results
        output_file = config.get("output", "scheduled_scan_results.json")
        save_results(all_results, output_file)

    else:
        logging.error(_("Failed to load config file for scheduled scan."))


# Function for advanced data analysis with machine learning
def advanced_data_analysis(results: List[Dict[str, Any]]) -> Optional[RandomForestClassifier]:
    try:
        # Convert data to DataFrame
        df = pd.DataFrame(results)
        # Add a dummy vulnerability column for demonstration
        df['vulnerability'] = np.random.choice([0, 1],
                                               size=len(df))  # Randomly assign vulnerabilities for demonstration

        # Features and labels
        X = df[['port', 'status']]
        y = df['vulnerability']

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Train Random Forest model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        # Predict and evaluate the model
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logging.info(f"Model accuracy: {accuracy}")

        return model
    except Exception as e:
        logging.error(f"Error in advanced data analysis: {e}")
    return None


# Function to detect suspicious traffic
def detect_suspicious_traffic(traffic_data: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
    try:
        # Analyze network traffic for suspicious behavior
        suspicious_patterns = []
        for entry in traffic_data:
            if entry['packet_size'] > 1000:  # Example: Large packets are suspicious
                suspicious_patterns.append(entry)
        return suspicious_patterns
    except Exception as e:
        logging.error(f"Error detecting suspicious traffic: {e}")
    return None


# Function to detect anomalies using Isolation Forest
def detect_anomalies(traffic_data: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
    try:
        # Convert data to NumPy array
        data = np.array([entry['packet_size'] for entry in traffic_data]).reshape(-1, 1)

        # Train Isolation Forest model
        model = IsolationForest(contamination=0.01)  # Contamination is the percentage of anomalies
        model.fit(data)

        # Predict anomalies
        anomalies = model.predict(data)

        # Flag anomalous behavior
        suspicious_traffic = [traffic_data[i] for i, anomaly in enumerate(anomalies) if anomaly == -1]
        return suspicious_traffic
    except Exception as e:
        logging.error(f"Error detecting anomalies: {e}")
    return None


# Function to generate security recommendations
def generate_security_recommendations(analysis: Dict[str, int]) -> List[str]:
    recommendations = []

    if analysis['open_ports'] > 10:
        recommendations.append("Too many open ports. Close unnecessary ports.")

    if analysis['common_ports_open'] > 5:
        recommendations.append("Many common ports are open. Ensure these ports are secure.")

    if analysis['filtered_ports'] > 0:
        recommendations.append("Some ports are filtered. Verify if these filters are correctly applied.")

    return recommendations


# Function to predict potential attacks
def predict_attacks(results: List[Dict[str, Any]]) -> Optional[RandomForestClassifier]:
    try:
        # Convert data to DataFrame
        df = pd.DataFrame(results)
        # Add a dummy vulnerability column for demonstration
        df['vulnerability'] = np.random.choice([0, 1],
                                               size=len(df))  # Randomly assign vulnerabilities for demonstration

        # Features and labels
        X = df[['port', 'status']]
        y = df['vulnerability']

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Train Random Forest model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        # Predict and evaluate the model
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logging.info(f"Model accuracy: {accuracy}")

        return model
    except Exception as e:
        logging.error(f"Error in attack prediction: {e}")
    return None


# Function to simulate high traffic for load testing
def load_test(target_ip: str, target_port: int, duration: int = 60, rate: int = 100) -> None:
    """
    Simulate high traffic to a specific service or port for performance testing.

    :param target_ip: Target IP address
    :param target_port: Target port
    :param duration: Test duration (seconds)
    :param rate: Number of requests per second
    """
    end_time = time.time() + duration
    request_count = 0
    success_count = 0
    failure_count = 0

    logging.info(f"Starting load test on {target_ip}:{target_port} for {duration} seconds at {rate} requests/second.")

    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, target_port))
            sock.close()
            success_count += 1
        except Exception as e:
            failure_count += 1
        request_count += 1
        time.sleep(1 / rate)

    logging.info(f"Load test completed. Requests: {request_count}, Success: {success_count}, Failures: {failure_count}")


# Function to evaluate server capacity
def evaluate_server_capacity(target_ip: str, target_port: int, max_rate: int = 1000, step: int = 100) -> None:
    """
    Evaluate server capacity under high traffic.

    :param target_ip: Target IP address
    :param target_port: Target port
    :param max_rate: Maximum request rate (requests per second)
    :param step: Increment step for request rate
    """
    results = []
    for rate in range(step, max_rate + 1, step):
        logging.info(f"Testing server capacity at {rate} requests/second.")
        start_time = time.time()
        load_test(target_ip, target_port, duration=10, rate=rate)
        elapsed_time = time.time() - start_time
        results.append({"rate": rate, "elapsed_time": elapsed_time})

    # Analyze results
    for result in results:
        logging.info(f"Rate: {result['rate']} req/s, Elapsed Time: {result['elapsed_time']}s")


# Function to check Modbus protocol
def check_modbus(ip: str, port: int = 502) -> None:
    """
    Check connection to a Modbus device and read data.

    :param ip: IP address of the Modbus device
    :param port: Modbus port (default 502)
    """
    try:
        client = ModbusClient.ModbusTcpClient(ip, port, timeout=5)  # Set timeout to 5 seconds
        client.connect()
        if client.connect():
            logging.info(f"Connected to Modbus device at {ip}:{port}")
            # Read data from Modbus device
            response = client.read_holding_registers(address=0, count=10, unit=1)
            if not response.isError():
                logging.info(f"Modbus data read successfully: {response.registers}")
            else:
                logging.error(f"Error reading Modbus data: {response}")
            client.close()
        else:
            logging.error(f"Failed to connect to Modbus device at {ip}:{port}")
    except Exception as e:
        logging.error(f"Error checking Modbus: {e}")


# Function to check MQTT protocol
def check_mqtt(broker_ip: str, port: int = 1883) -> None:
    """
    Check connection to an MQTT broker and send/receive messages.

    :param broker_ip: IP address of the MQTT broker
    :param port: MQTT port (default 1883)
    """
    try:
        client = mqtt.Client()
        client.connect(broker_ip, port, 60)
        logging.info(f"Connected to MQTT broker at {broker_ip}:{port}")

        # Publish a message
        client.publish("test/topic", "Hello MQTT")
        logging.info("Message published to MQTT broker")

        # Receive a message
        def on_message(client, userdata, msg):
            logging.info(f"Received message: {msg.payload.decode()}")

        client.subscribe("test/topic")
        client.on_message = on_message
        client.loop_start()
        time.sleep(2)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        logging.error(f"Error checking MQTT: {e}")


# Function to check CoAP protocol
async def check_coap(ip: str, port: int = 5683) -> None:
    """
    Check connection to a CoAP server and send/receive messages.

    :param ip: IP address of the CoAP server
    :param port: CoAP port (default 5683)
    """
    try:
        protocol = await coap.Context.create_client_context()
        request = coap.Message(code=coap.GET, uri=f"coap://{ip}:{port}/test")
        response = await asyncio.wait_for(protocol.request(request).response, timeout=5)  # Set timeout to 5 seconds
        logging.info(f"CoAP response: {response.payload.decode()}")
    except Exception as e:
        logging.error(f"Error checking CoAP: {e}")


# Function to check encryption protocols (SSH, HTTPS, TLS)
def check_encryption_protocols(ip: str, port: int) -> None:
    """
    Check encryption protocols such as SSH, HTTPS, and TLS.

    :param ip: Target IP address
    :param port: Target port
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=5) as sock:  # Set timeout to 5 seconds
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                logging.info(f"Connected to {ip}:{port} using {ssock.version()}")
                cert = ssock.getpeercert()
                logging.info(f"Certificate: {cert}")
                # Check certificate validity
                if cert:
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if datetime.now() > not_after:
                        logging.warning(f"Certificate for {ip}:{port} has expired.")
                    else:
                        logging.info(f"Certificate for {ip}:{port} is valid.")
    except Exception as e:
        logging.error(f"Error checking encryption protocols: {e}")


# Function to identify vulnerable ports
def identify_vulnerable_ports(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify vulnerable ports that are commonly targeted by attacks.

    :param results: Port scan results
    """
    vulnerable_ports = []
    for result in results:
        if result["status"] == "open" and result["port"] in VULNERABLE_PORTS:
            vulnerable_ports.append(result)
    return vulnerable_ports


# Function to identify insecure configuration files
def identify_insecure_config_files(target_ip: str) -> List[str]:
    """
    Identify insecure configuration files such as .htaccess or FTP configurations with default passwords.

    :param target_ip: Target IP address
    """
    insecure_files = []
    try:
        # Check for .htaccess files
        response = requests.get(f"http://{target_ip}/.htaccess", timeout=5)  # Set timeout to 5 seconds
        if response.status_code == 200:
            insecure_files.append(".htaccess")

        # Check FTP configurations with default credentials
        from ftplib import FTP
        ftp = FTP(target_ip)
        ftp.login("anonymous", "anonymous")
        insecure_files.append("FTP with default credentials")
        ftp.quit()
    except Exception as e:
        logging.error(f"Error identifying insecure config files: {e}")
    return insecure_files


# Function to identify management ports
def identify_management_ports(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify open management ports such as RDP, VNC, or Web Admin.

    :param results: Port scan results
    """
    management_ports = []
    for result in results:
        if result["status"] == "open" and result["port"] in MANAGEMENT_PORTS:
            management_ports.append(result)
    return management_ports


# Function to check IP against local threat intelligence
def check_threat_intelligence(ip: str) -> bool:
    """
    Check IP against a local list of known malicious IPs.

    :param ip: IP address to check
    """
    if ip in MALICIOUS_IPS:
        logging.warning(f"IP {ip} is flagged as malicious in local threat intelligence.")
        return True
    return False


# Function to send email alerts
def send_email_alert(subject: str, message: str) -> None:
    """
    Send an alert via email.

    :param subject: Email subject
    :param message: Email message
    """
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = EMAIL_SETTINGS['email_address']
        msg['To'] = EMAIL_SETTINGS['recipient_email']

        with smtplib.SMTP(EMAIL_SETTINGS['smtp_server'], EMAIL_SETTINGS['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_SETTINGS['email_address'], EMAIL_SETTINGS['email_password'])
            server.sendmail(EMAIL_SETTINGS['email_address'], EMAIL_SETTINGS['recipient_email'], msg.as_string())
        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Error sending email alert: {e}")


# Function to send webhook alerts
def send_webhook_alert(message: str) -> None:
    """
    Send an alert via webhook (e.g., Slack).

    :param message: Message to send
    """
    try:
        payload = {"text": message}
        response = requests.post(WEBHOOK_URL, json=payload)
        if response.status_code == 200:
            logging.info("Webhook alert sent successfully.")
        else:
            logging.error(f"Error sending webhook alert: {response.status_code}")
    except Exception as e:
        logging.error(f"Error sending webhook alert: {e}")


# Function to identify IoT devices
def identify_iot_devices(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify IoT devices based on open ports and services.

    :param results: Port scan results
    """
    iot_devices = []
    for result in results:
        if result["status"] == "open" and result["port"] in IOT_PORTS:
            iot_devices.append(result)
    return iot_devices


# Function to evaluate IoT vulnerabilities
def evaluate_iot_vulnerabilities(results: List[Dict[str, Any]]) -> List[str]:
    """
    Evaluate vulnerabilities in IoT devices based on open ports and services.

    :param results: Port scan results
    """
    vulnerabilities = []
    for result in results:
        if result["status"] == "open" and result["port"] in IOT_PORTS:
            if result["port"] == 1883:  # MQTT
                vulnerabilities.append("MQTT service is open. Ensure it is secured with authentication and encryption.")
            elif result["port"] == 5683:  # CoAP
                vulnerabilities.append("CoAP service is open. Ensure it is secured with DTLS.")
            elif result["port"] == 8080:  # HTTP
                vulnerabilities.append("HTTP service is open. Ensure it is secured with HTTPS.")
    return vulnerabilities


# Function to compare current scan results with previous results
def compare_with_previous_scan(current_results: List[Dict[str, Any]], previous_results_file: str) -> Optional[
    Dict[str, List[Dict[str, Any]]]]:
    """
    Compare current scan results with previous scan results to identify changes.

    :param current_results: Current scan results
    :param previous_results_file: File containing previous scan results
    """
    try:
        if not os.path.exists(previous_results_file):
            logging.warning(f"No previous scan results found at {previous_results_file}.")
            return None

        with open(previous_results_file, 'r') as f:
            previous_results = json.load(f)["results"]

        current_ports = {result["port"]: result for result in current_results}
        previous_ports = {result["port"]: result for result in previous_results}

        changes = {
            "new_ports": [],
            "closed_ports": [],
            "status_changes": [],
        }

        # Check for new ports
        for port, result in current_ports.items():
            if port not in previous_ports:
                changes["new_ports"].append(result)

        # Check for closed ports
        for port, result in previous_ports.items():
            if port not in current_ports:
                changes["closed_ports"].append(result)

        # Check for status changes
        for port, current_result in current_ports.items():
            if port in previous_ports:
                previous_result = previous_ports[port]
                if current_result["status"] != previous_result["status"]:
                    changes["status_changes"].append({
                        "port": port,
                        "previous_status": previous_result["status"],
                        "current_status": current_result["status"],
                    })

        return changes
    except Exception as e:
        logging.error(f"Error comparing with previous scan: {e}")
    return None


# Function to generate historical reports
def generate_historical_report(scan_history_file: str) -> Optional[Dict[str, List[int]]]:
    """
    Generate a historical report based on past scan results.

    :param scan_history_file: File containing historical scan results
    """
    try:
        if not os.path.exists(scan_history_file):
            logging.warning(f"No scan history found at {scan_history_file}.")
            return None

        with open(scan_history_file, 'r') as f:
            scan_history = json.load(f)

        report = {
            "total_scans": len(scan_history),
            "open_ports_over_time": [],
            "closed_ports_over_time": [],
            "vulnerable_ports_over_time": [],
        }

        for scan in scan_history:
            report["open_ports_over_time"].append(len([r for r in scan["results"] if r["status"] == "open"]))
            report["closed_ports_over_time"].append(len([r for r in scan["results"] if r["status"] == "closed"]))
            report["vulnerable_ports_over_time"].append(
                len([r for r in scan["results"] if r["status"] == "open" and r["port"] in VULNERABLE_PORTS]))

        return report
    except Exception as e:
        logging.error(f"Error generating historical report: {e}")
    return None


# Function to perform a full scan
def full_scan(target: str, ports: List[int], scan_type: str = "tcp", timeout: int = 1, max_threads: int = 100,
              version_detection: bool = False, os_detection: bool = False, random_scan: bool = False,
              priority_scan: bool = False, custom_scan: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Perform a full scan on a target IP address.

    :param target: Target IP address
    :param ports: List of ports to scan
    :param scan_type: Type of scan (tcp, udp, syn)
    :param timeout: Timeout for each scan
    :param max_threads: Maximum number of threads
    :param version_detection: Enable service version detection
    :param os_detection: Enable OS detection
    :param random_scan: Scan ports in random order
    :param priority_scan: Scan common ports first
    :param custom_scan: Custom scan type (xmas, fin, null)
    :return: List of scan results
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        if random_scan:
            random.shuffle(ports)
        if priority_scan:
            ports = sorted(ports, key=lambda x: x in COMMON_PORTS, reverse=True)
        for port in ports:
            if scan_type == "tcp":
                futures.append(executor.submit(scan_tcp_port, target, port, timeout, version_detection, os_detection))
            elif scan_type == "udp":
                futures.append(executor.submit(scan_udp_port, target, port, timeout))
            elif scan_type == "syn":
                futures.append(executor.submit(scan_syn_port, target, port, timeout))

        for future in as_completed(futures):
            port, status, service = future.result()
            results.append({"ip": target, "port": port, "status": status, "service": service})

    return results


# Function to perform a distributed scan
def distributed_scan(targets: List[str], ports: List[int], scan_type: str = "tcp", timeout: int = 1,
                     max_threads: int = 100, workers: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Perform a distributed scan across multiple workers.

    :param targets: List of target IP addresses
    :param ports: List of ports to scan
    :param scan_type: Type of scan (tcp, udp, syn)
    :param timeout: Timeout for each scan
    :param max_threads: Maximum number of threads
    :param workers: List of worker IP addresses
    :return: List of scan results
    """
    results = []
    if workers:
        # Distribute the scan across workers
        for worker in workers:
            logging.info(f"Distributing scan to worker: {worker}")
            # Here you would typically send the scan task to the worker
            # For simplicity, we assume the worker performs the same scan as the main function
            worker_results = full_scan(targets[0], ports, scan_type, timeout, max_threads)
            results.extend(worker_results)
    else:
        # If no workers are specified, perform the scan locally
        results = full_scan(targets[0], ports, scan_type, timeout, max_threads)

    return results


# Function to perform an asynchronous full scan
async def async_full_scan(target: str, ports: List[int], scan_type: str = "tcp", timeout: int = 1,
                          max_threads: int = 100, version_detection: bool = False, os_detection: bool = False,
                          random_scan: bool = False, priority_scan: bool = False) -> List[Dict[str, Any]]:
    """
    Perform an asynchronous full scan on a target IP address.

    :param target: Target IP address
    :param ports: List of ports to scan
    :param scan_type: Type of scan (tcp, udp, syn)
    :param timeout: Timeout for each scan
    :param max_threads: Maximum number of threads
    :param version_detection: Enable service version detection
    :param os_detection: Enable OS detection
    :param random_scan: Scan ports in random order
    :param priority_scan: Scan common ports first
    :return: List of scan results
    """
    results = []
    tasks = []
    if random_scan:
        random.shuffle(ports)
    if priority_scan:
        ports = sorted(ports, key=lambda x: x in COMMON_PORTS, reverse=True)
    for port in ports:
        if scan_type == "tcp":
            tasks.append(
                asyncio.create_task(async_scan_tcp_port(target, port, timeout, version_detection, os_detection)))
        elif scan_type == "udp":
            tasks.append(asyncio.create_task(scan_udp_port(target, port, timeout)))
        elif scan_type == "syn":
            tasks.append(asyncio.create_task(scan_syn_port(target, port, timeout)))

    for task in tasks:
        port, status, service = await task
        results.append({"ip": target, "port": port, "status": status, "service": service})

    return results


# Main function
def main():
    parser = argparse.ArgumentParser(description=_("Advanced Port Scanner"))
    parser.add_argument("targets", help=_("Target IP addresses (comma-separated or CIDR)"))
    parser.add_argument("-p", "--ports", help=_("Port range (e.g., 1-100) or specific ports (e.g., 80,443)"),
                        default="1-1024")
    parser.add_argument("-t", "--type", help=_("Scan type (tcp, udp, syn)"), default="tcp")
    parser.add_argument("-T", "--timeout", help=_("Timeout for each scan (in seconds)"), type=float, default=1)
    parser.add_argument("-m", "--max-threads", help=_("Maximum number of threads"), type=int, default=100)
    parser.add_argument("-O", "--os-detection", help=_("Enable OS detection"), action="store_true")
    parser.add_argument("-V", "--version-detection", help=_("Enable service version detection"), action="store_true")
    parser.add_argument("-o", "--output",
                        help=_("Output file to save results (supports .txt, .json, .csv, .xml, .html, .pdf)"))
    parser.add_argument("-i", "--input", help=_("Input file containing list of targets (one per line)"))
    parser.add_argument("-r", "--rate-limit", help=_("Rate limit in requests per second"), type=int, default=0)
    parser.add_argument("--random-scan", help=_("Scan ports in random order"), action="store_true")
    parser.add_argument("--priority-scan", help=_("Scan common ports first"), action="store_true")
    parser.add_argument("--country-filter", help=_("Filter targets by country code (e.g., US, IR)"), type=str)
    parser.add_argument("--custom-scan", help=_("Custom scan type (xmas, fin, null)"), type=str)
    parser.add_argument("--discover-local", help=_("Discover local devices (IPv4 and IPv6)"), action="store_true")
    parser.add_argument("--traceroute", help=_("Perform traceroute to target"), action="store_true")
    parser.add_argument("--distributed", help=_("Enable distributed scanning (comma-separated list of workers)"),
                        type=str)
    parser.add_argument("--async-scan", help=_("Enable asynchronous scanning"), action="store_true")
    parser.add_argument("--filter-ports", help=_("Filter ports to scan (e.g., 80,443)"), type=str)
    parser.add_argument("--filter-protocols", help=_("Filter protocols to scan (e.g., tcp,udp)"), type=str)
    parser.add_argument("--generate-charts", help=_("Generate charts for scan results"), action="store_true")
    parser.add_argument("--use-tor", help=_("Use Tor for anonymity"), action="store_true")
    parser.add_argument("--encrypt-data", help=_("Encrypt data before saving or sending"), action="store_true")
    parser.add_argument("--config", help=_("Load scan settings from a config file"), type=str)
    parser.add_argument("--schedule", help=_("Schedule scans at specific intervals (e.g., '1h' for hourly)"), type=str)
    parser.add_argument("--vulnerability-scan", help=_("Enable vulnerability scanning"), action="store_true")
    parser.add_argument("--check-default-files", help=_("Check for default or insecure files"), action="store_true")
    parser.add_argument("--check-crypto", help=_("Check for crypto vulnerabilities"), action="store_true")
    parser.add_argument("--advanced-analysis", help=_("Enable advanced data analysis with machine learning"),
                        action="store_true")
    parser.add_argument("--detect-suspicious-traffic", help=_("Detect suspicious traffic patterns"),
                        action="store_true")
    parser.add_argument("--load-test", help=_("Perform a load test on a specific port"), action="store_true")
    parser.add_argument("--evaluate-capacity", help=_("Evaluate server capacity under high traffic"),
                        action="store_true")
    parser.add_argument("--check-modbus", help=_("Check Modbus protocol on target"), action="store_true")
    parser.add_argument("--check-mqtt", help=_("Check MQTT protocol on target"), action="store_true")
    parser.add_argument("--check-coap", help=_("Check CoAP protocol on target"), action="store_true")
    parser.add_argument("--check-encryption", help=_("Check encryption protocols (SSH, HTTPS, TLS) on target"),
                        action="store_true")
    parser.add_argument("--identify-vulnerable-ports", help=_("Identify vulnerable ports"), action="store_true")
    parser.add_argument("--identify-insecure-configs", help=_("Identify insecure configuration files"),
                        action="store_true")
    parser.add_argument("--identify-management-ports", help=_("Identify open management ports"), action="store_true")
    parser.add_argument("--threat-intelligence", help=_("Check IPs against local threat intelligence"),
                        action="store_true")
    parser.add_argument("--send-alerts", help=_("Send alerts via email or webhook"), action="store_true")
    parser.add_argument("--identify-iot-devices", help=_("Identify IoT devices"), action="store_true")
    parser.add_argument("--evaluate-iot-vulnerabilities", help=_("Evaluate IoT vulnerabilities"), action="store_true")
    parser.add_argument("--compare-previous", help=_("Compare current scan results with previous scan"),
                        action="store_true")
    parser.add_argument("--generate-historical-report", help=_("Generate a historical report based on past scans"),
                        action="store_true")

    args = parser.parse_args()

    # Set language
    if args.language:
        gettext.translation('messages', LOCALE_DIR, languages=[args.language]).install()

    # Load configuration from file
    if args.config:
        config = load_config(args.config)
        if config:
            logging.info(_("Loaded config from {}").format(args.config))
            # Apply configuration from file
            targets = config.get("targets", [])
            ports = config.get("ports", "1-1024")
            scan_type = config.get("type", "tcp")
            timeout = config.get("timeout", 1)
            max_threads = config.get("max_threads", 100)
            rate_limit_value = config.get("rate_limit", 0)
            output_file = config.get("output", "scan_results.json")
        else:
            logging.error(_("Failed to load config file."))

    # Start Tor if enabled
    tor_process = None
    if args.use_tor:
        tor_process = start_tor()
        if tor_process:
            logging.info(_("Tor is running."))

    # Read target list from file or argument
    if args.input:
        with open(args.input, 'r') as f:
            targets = [line.strip() for line in f.readlines()]
    else:
        targets = args.targets.split(',')

    # Expand CIDR to list of IPs
    expanded_targets = []
    for target in targets:
        if '/' in target:
            expanded_targets.extend([str(ip) for ip in ip_network(target, strict=False)])
        else:
            expanded_targets.append(target)

    # Filter IPs by country
    if args.country_filter:
        filtered_targets = []
        for ip in expanded_targets:
            country = get_geolocation(ip)["country"] if get_geolocation(ip) else None
            if country == args.country_filter:
                filtered_targets.append(ip)
        expanded_targets = filtered_targets

    # Read ports
    if ',' in args.ports:
        ports = list(map(int, args.ports.split(',')))
    else:
        start_port, end_port = map(int, args.ports.split('-'))
        ports = range(start_port, end_port + 1)

    # Filter ports
    if args.filter_ports:
        filter_ports = list(map(int, args.filter_ports.split(',')))
        ports = [port for port in ports if port in filter_ports]

    # Filter protocols
    if args.filter_protocols:
        filter_protocols = args.filter_protocols.split(',')
        if "tcp" not in filter_protocols:
            ports = [port for port in ports if port not in COMMON_PORTS]

    all_results = []

    # Distributed scan
    if args.distributed:
        workers = args.distributed.split(',')
        all_results = distributed_scan(expanded_targets, ports, args.type, args.timeout, args.max_threads, workers)
    # Async scan
    elif args.async_scan:
        loop = asyncio.get_event_loop()
        for target in expanded_targets:
            logging.info(_("Scanning target: {}").format(target))
            results = loop.run_until_complete(
                async_full_scan(target, ports, args.type, args.timeout, args.max_threads, args.version_detection,
                                args.os_detection, args.random_scan, args.priority_scan))
            all_results.extend(results)
    # Normal scan
    else:
        for target in expanded_targets:
            logging.info(_("Scanning target: {}").format(target))
            if args.rate_limit > 0:
                rate_limit(args.rate_limit)
            results = full_scan(target, ports, args.type, args.timeout, args.max_threads, args.version_detection,
                                args.os_detection, args.random_scan, args.priority_scan, args.custom_scan)
            all_results.extend(results)

    # Analyze data
    analysis = analyze_data(all_results)
    logging.info(_("Analysis: {}").format(analysis))

    # Encrypt data if enabled
    if args.encrypt_data:
        encrypted_results = encrypt_data(json.dumps(all_results))
        if encrypted_results:
            logging.info(_("Data has been encrypted."))

    # Save results
    if args.output:
        save_results(all_results, args.output, analysis)

    # Generate charts
    if args.generate_charts:
        create_charts(all_results, args.output)

    # Create IP location map
    create_ip_map(all_results)

    # Schedule automatic scans
    if args.schedule:
        schedule.every().hour.do(scheduled_scan, args.config)
        while True:
            schedule.run_pending()
            time.sleep(1)

    # Advanced data analysis with machine learning
    if args.advanced_analysis:
        model = advanced_data_analysis(all_results)
        if model:
            logging.info(_("Advanced data analysis completed."))

    # Detect suspicious traffic
    if args.detect_suspicious_traffic:
        suspicious_traffic = detect_suspicious_traffic(all_results)
        if suspicious_traffic:
            logging.info(_("Suspicious traffic patterns detected: {}").format(suspicious_traffic))

    # Detect anomalous behavior
    suspicious_traffic = detect_anomalies(all_results)
    if suspicious_traffic:
        logging.info(_("Suspicious traffic detected: {}").format(suspicious_traffic))

    # Generate security recommendations
    recommendations = generate_security_recommendations(analysis)
    if recommendations:
        logging.info(_("Security recommendations: {}").format(recommendations))

    # Predict potential attacks
    attack_model = predict_attacks(all_results)
    if attack_model:
        logging.info(_("Attack prediction model trained successfully."))

    # Load testing
    if args.load_test:
        target_ip = expanded_targets[0]  # Use the first target for load testing
        target_port = ports[0]  # Use the first port for load testing
        load_test(target_ip, target_port, duration=60, rate=100)

    # Evaluate server capacity
    if args.evaluate_capacity:
        target_ip = expanded_targets[0]  # Use the first target for capacity evaluation
        target_port = ports[0]  # Use the first port for capacity evaluation
        evaluate_server_capacity(target_ip, target_port, max_rate=1000, step=100)

    # Check Modbus protocol
    if args.check_modbus:
        target_ip = expanded_targets[0]  # Use the first target for Modbus check
        check_modbus(target_ip)

    # Check MQTT protocol
    if args.check_mqtt:
        target_ip = expanded_targets[0]  # Use the first target for MQTT check
        check_mqtt(target_ip)

    # Check CoAP protocol
    if args.check_coap:
        target_ip = expanded_targets[0]  # Use the first target for CoAP check
        asyncio.run(check_coap(target_ip))

    # Check encryption protocols
    if args.check_encryption:
        target_ip = expanded_targets[0]  # Use the first target for encryption check
        for port in [22, 443, 8443]:  # Ports for SSH, HTTPS, and TLS
            check_encryption_protocols(target_ip, port)

    # Identify vulnerable ports
    if args.identify_vulnerable_ports:
        vulnerable_ports = identify_vulnerable_ports(all_results)
        if vulnerable_ports:
            logging.info(_("Vulnerable ports detected: {}").format(vulnerable_ports))

    # Identify insecure configuration files
    if args.identify_insecure_configs:
        target_ip = expanded_targets[0]  # Use the first target for insecure config check
        insecure_files = identify_insecure_config_files(target_ip)
        if insecure_files:
            logging.info(_("Insecure configuration files detected: {}").format(insecure_files))

    # Identify management ports
    if args.identify_management_ports:
        management_ports = identify_management_ports(all_results)
        if management_ports:
            logging.info(_("Open management ports detected: {}").format(management_ports))

    # Check IPs against local threat intelligence
    if args.threat_intelligence:
        for target in expanded_targets:
            if check_threat_intelligence(target):
                logging.warning(f"IP {target} is flagged as malicious.")
                if args.send_alerts:
                    send_email_alert("Malicious IP Detected", f"IP {target} is flagged as malicious.")
                    send_webhook_alert(f"Malicious IP Detected: {target}")

    # Identify IoT devices
    if args.identify_iot_devices:
        iot_devices = identify_iot_devices(all_results)
        if iot_devices:
            logging.info(_("IoT devices detected: {}").format(iot_devices))

    # Evaluate IoT vulnerabilities
    if args.evaluate_iot_vulnerabilities:
        iot_vulnerabilities = evaluate_iot_vulnerabilities(all_results)
        if iot_vulnerabilities:
            logging.info(_("IoT vulnerabilities detected: {}").format(iot_vulnerabilities))

    # Compare with previous scan
    if args.compare_previous:
        previous_results_file = "previous_scan_results.json"
        if os.path.exists(previous_results_file):
            changes = compare_with_previous_scan(all_results, previous_results_file)
            if changes:
                logging.info(_("Changes detected compared to previous scan: {}").format(changes))
        else:
            logging.warning(_("No previous scan results found for comparison."))

    # Generate historical report
    if args.generate_historical_report:
        scan_history_file = "scan_history.json"
        if os.path.exists(scan_history_file):
            report = generate_historical_report(scan_history_file)
            if report:
                logging.info(_("Historical report generated: {}").format(report))
        else:
            logging.warning(_("No scan history found for generating historical report."))

    # Stop Tor if enabled
    if tor_process:
        tor_process.terminate()
        logging.info(_("Tor has been stopped."))


if __name__ == "__main__":
    main()