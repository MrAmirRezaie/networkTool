# Advanced Port Scanner

This script is an advanced port scanner that allows you to identify open, closed, and filtered ports on one or more specified targets. It supports various scanning techniques such as TCP, UDP, and SYN scans, and offers advanced features like service version detection, OS detection, distributed scanning, and machine learning-based data analysis.

---

## Key Features

- **TCP, UDP, and SYN Scanning**: Support for different types of port scanning.
- **Service Version Detection**: Detect the version of services running on open ports.
- **OS Detection**: Attempt to detect the target's operating system.
- **Distributed Scanning**: Scan using multiple workers to increase speed.
- **Machine Learning Analysis**: Analyze scan data to identify suspicious patterns and predict potential attacks.
- **Tor Support**: Use Tor for anonymous scanning.
- **Alerting**: Send alerts via email or webhook.
- **IoT Device Identification**: Identify IoT devices based on open ports.
- **Vulnerability Assessment**: Evaluate vulnerabilities in IoT devices and open ports.

---

## Installation

- To use this script, ensure you have Python 3.7 or higher installed. Then, install the required libraries:

    ```bash
    pip install -r requirements.txt
    ```
    **OR**
    ```bash
    pip install --break-system-packages -r requirements.txt
    ```

---

## Usage

- The script is executed via the command line and supports numerous options. Below are some commands and examples:

---

### **Basic Scan**:
- To scan a target with the default port range (1-1024):
    ```bash
    python main.py 192.168.1.1
    ```

### **Scan with Specific Port Range**:
- To scan a target with a specific port range:
    ```bash
    python main.py 192.168.1.1 -p 1-1000
    ```

### **Scan with Specific Type**:
- To scan with a specific type (e.g., UDP):
    ```bash
    python main.py 192.168.1.1 -t udp
    ```

### **Scan with Service Version Detection**:
- To scan with service version detection:
    ```bash
    python main.py 192.168.1.1 -V
    ```

### **Scan with OS Detection**:
- To scan with OS detection:
    ```bash
    python main.py 192.168.1.1 -O
    ```

### **Distributed Scan**:
- To perform a distributed scan using multiple workers:
    ```bash
    python main.py 192.168.1.1 --distributed 192.168.1.2,192.168.1.3
    ```

### **Use Tor**:
- To perform an anonymous scan using Tor:
    ```bash
    python main.py 192.168.1.1 --use-tor
    ```

### **Send Alerts**:
- To send alerts via email or webhook:
    ```bash
    python main.py 192.168.1.1 --send-alerts
    ```

### **Identify IoT Devices**:
- To identify IoT devices:
    ```bash
    python main.py 192.168.1.1 --identify-iot-devices
    ```

### **Evaluate IoT Vulnerabilities**:
- To evaluate IoT device vulnerabilities:
    ```bash
    python main.py 192.168.1.1 --evaluate-iot-vulnerabilities
    ```

### **Machine Learning Analysis**:
- To perform machine learning-based data analysis:
    ```bash
    python main.py 192.168.1.1 --advanced-analysis
    ```

### **Rate-Limited Scan**:
- To perform a rate-limited scan (e.g., 10 requests per second):
    ```bash
    python main.py 192.168.1.1 --rate-limit 10
    ```

### **Save Results**:
- To save scan results to a file:
    ```bash
    python main.py 192.168.1.1 -o results.json
    ```

### **Generate Charts**:
- To generate charts from scan results:
    ```bash
    python main.py 192.168.1.1 --generate-charts
    ```

### **Scheduled Scan**:
- To perform a scheduled scan (e.g., every hour):
    ```bash
    python main.py 192.168.1.1 --schedule 1h
    ```

### **Identify Management Ports**:
- To identify open management ports:
    ```bash
    python main.py 192.168.1.1 --identify-management-ports
    ```

### **Identify Insecure Configuration Files**:
- To identify insecure configuration files:
    ```bash
    python main.py 192.168.1.1 --identify-insecure-configs
    ```

### **Check Encryption Protocols**:
- To check encryption protocols (SSH, HTTPS, TLS):
    ```bash
    python main.py 192.168.1.1 --check-encryption
    ```

### **Check Modbus Protocol**:
- To check the Modbus protocol:
    ```bash
    python main.py 192.168.1.1 --check-modbus
    ```

### **Check MQTT Protocol**:
- To check the MQTT protocol:
    ```bash
    python main.py 192.168.1.1 --check-mqtt
    ```

### **Check CoAP Protocol**:
- To check the CoAP protocol:
    ```bash
    python main.py 192.168.1.1 --check-coap
    ```

### **Compare with Previous Scan**:
- To compare current scan results with a previous scan:
    ```bash
    python main.py 192.168.1.1 --compare-previous
    ```

### **Generate Historical Report**:
- To generate a historical report based on past scans:
    ```bash
    python main.py 192.168.1.1 --generate-historical-report
    ```

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `targets` | Target IP addresses (comma-separated or CIDR) |
| `-p`, `--ports` | Port range (e.g., 1-100) or specific ports (e.g., 80,443) |
| `-t`, `--type` | Scan type (`tcp`, `udp`, `syn`) |
| `-T`, `--timeout` | Timeout for each scan (in seconds) |
| `-m`, `--max-threads` | Maximum number of threads |
| `-O`, `--os-detection` | Enable OS detection |
| `-V`, `--version-detection` | Enable service version detection |
| `-o`, `--output` | Output file to save results (supports `.txt`, `.json`, `.csv`, `.xml`, `.html`, `.pdf`) |
| `-i`, `--input` | Input file containing a list of targets (one per line) |
| `-r`, `--rate-limit` | Rate limit in requests per second |
| `--random-scan` | Scan ports in random order |
| `--priority-scan` | Scan common ports first |
| `--country-filter` | Filter targets by country code (e.g., `US`, `IR`) |
| `--custom-scan` | Custom scan type (`xmas`, `fin`, `null`) |
| `--discover-local` | Discover local devices (IPv4 and IPv6) |
| `--traceroute` | Perform traceroute to the target |
| `--distributed` | Enable distributed scanning (comma-separated list of workers) |
| `--async-scan` | Enable asynchronous scanning |
| `--filter-ports` | Filter ports to scan (e.g., `80,443`) |
| `--filter-protocols` | Filter protocols to scan (e.g., `tcp,udp`) |
| `--generate-charts` | Generate charts for scan results |
| `--use-tor` | Use Tor for anonymity |
| `--encrypt-data` | Encrypt data before saving or sending |
| `--config` | Load scan settings from a config file |
| `--schedule` | Schedule scans at specific intervals (e.g., `1h` for hourly) |
| `--vulnerability-scan` | Enable vulnerability scanning |
| `--check-default-files` | Check for default or insecure files |
| `--check-crypto` | Check for crypto vulnerabilities |
| `--advanced-analysis` | Enable advanced data analysis with machine learning |
| `--detect-suspicious-traffic` | Detect suspicious traffic patterns |
| `--load-test` | Perform a load test on a specific port |
| `--evaluate-capacity` | Evaluate server capacity under high traffic |
| `--check-modbus` | Check Modbus protocol on the target |
| `--check-mqtt` | Check MQTT protocol on the target |
| `--check-coap` | Check CoAP protocol on the target |
| `--check-encryption` | Check encryption protocols (SSH, HTTPS, TLS) on the target |
| `--identify-vulnerable-ports` | Identify vulnerable ports |
| `--identify-insecure-configs` | Identify insecure configuration files |
| `--identify-management-ports` | Identify open management ports |
| `--threat-intelligence` | Check IPs against local threat intelligence |
| `--send-alerts` | Send alerts via email or webhook |
| `--identify-iot-devices` | Identify IoT devices |
| `--evaluate-iot-vulnerabilities` | Evaluate IoT vulnerabilities |
| `--compare-previous` | Compare current scan results with a previous scan |
| `--generate-historical-report` | Generate a historical report based on past scans |
| `--scan-website` | Scan a website for vulnerabilities |

---

## Examples

- **Scan a Target with Port Range 1-1000 and Save Results to JSON**:
    ```bash
    python main.py 192.168.1.1 -p 1-1000 -o results.json
    ```

- **Distributed Scan Using Two Workers**:
    ```bash
    python main.py 192.168.1.1 --distributed 192.168.1.2,192.168.1.3
    ```

- **Scan with Service Version and OS Detection**:
    ```bash
    python main.py 192.168.1.1 -V -O
    ```

- **Scan Using Tor and Send Alerts**:
    ```bash
    python main.py 192.168.1.1 --use-tor --send-alerts
    ```

- **Scheduled Scan Every Hour**:
    ```bash
    python main.py 192.168.1.1 --schedule 1h
    ```

---

## Security Notes

- Use this script only for legal purposes and with proper authorization.
- Ensure you have permission from the target system owner before scanning.
- Using Tor may reduce scan speed but increases anonymity.

---

## Contributing

- If you would like to contribute to the development of this project, please submit a Pull Request or report new Issues.

---

## License

- This project is licensed under the MIT License. For more information, see the [LICENSE](https://github.com/MrAmirRezaie/networkTool/blob/main/LICENSE) file.

## Contact
For questions, feedback, or bug reports, contact the maintainer:
- **Email**: MrAmirRezaie70@gmail.com
- **Telegram**: [@MrAmirRezaie](https://t.me/MrAmirRezaie)
- **GitHub**: [MrAmirRezaie](https://github.com/MrAmirRezaie/)
---

**Enjoy using the Advanced Port Scanner! 🚀**