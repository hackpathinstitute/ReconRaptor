# ReconRaptor

ReconRaptor is a comprehensive web application and network penetration testing tool that combines web scanning, network reconnaissance, and vulnerability assessment capabilities.

## Features

- 🌐 **Web Application Scanning**
  - Website information gathering
  - Technology stack detection
  - Server fingerprinting
  - Headers analysis
  - Directory and file enumeration (coming soon)
  - Login form brute-forcing (coming soon)

- 🔍 **Advanced Network Scanning**
  - Port scanning and service detection
  - Operating system fingerprinting
  - Service version detection
  - NSE (Nmap Scripting Engine) vulnerability scanning
  - Aggressive scanning mode for detailed enumeration
  - Customizable port ranges and scan types

- 🎯 **Host Discovery**
  - Network range scanning (CIDR format)
  - Multiple discovery methods (ICMP, ARP, TCP SYN/ACK, UDP)
  - MAC address and vendor detection
  - Hostname resolution
  - Comprehensive host enumeration

- 📊 **Reporting**
  - Detailed HTML reports
  - JSON raw data export
  - Summary reports with key findings
  - Network scan results integration
  - Host discovery results

```


```
## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Linux-based operating system
- pip package manager
- python3-venv package
- python3-full package

### Installation Steps

1. Install required system packages:
```bash
# Update package lists
sudo apt update

3. Install system dependencies:
```bash
# For Debian/Ubuntu
sudo apt-get install nmap

# For RHEL/CentOS
sudo yum install nmap

# For macOS
brew install nmap

# Install required packages
sudo apt install -y python3-venv python3-full python3-pip
```

2. Clone the repository:
```bash
git clone https://github.com/yourusername/ReconRaptor.git
cd ReconRaptor
```

3. Create and activate a virtual environment:
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # For Linux/macOS
# or
.\venv\Scripts\activate  # For Windows

# Verify you're using the virtual environment's Python
which python  # Should show path to .venv/bin/python
```

4. Install dependencies in the virtual environment:
```bash
# Upgrade pip in the virtual environment
python -m pip install --upgrade pip

# Install dependencies
python -m pip install -r requirements.txt
```

5. Verify installation:
```bash
python -m reconraptor.interface --version

## Usage

### Basic Usage

```bash
python3 reconraptor.py target.com
```

### Network Scanning Options

1. **Basic Network Scan**
```bash
# Scan with default options (common ports)
python3 reconraptor.py target.com

# Scan specific ports
python3 reconraptor.py target.com --ports "80,443,8080"

# Scan port range
python3 reconraptor.py target.com --ports "1-1000"
```

2. **Advanced Network Scanning**
```bash
# Enable aggressive scanning (includes OS detection and NSE scripts)
python3 reconraptor.py target.com --aggressive

# Network-only scan (skip web application scanning)
python3 reconraptor.py target.com --skip-web

# Custom port range with aggressive scanning
python3 reconraptor.py target.com --aggressive --ports "1-65535"
```

3. **Host Discovery**
```bash
# Scan network range with all discovery methods
python3 reconraptor.py 192.168.1.0/24 --network-scan

# Use specific discovery method
python3 reconraptor.py 192.168.1.0/24 --network-scan --discovery ping

# Scan IP range with ARP
python3 reconraptor.py 192.168.1.1-254 --network-scan --discovery arp

# Combine host discovery with aggressive scanning
python3 reconraptor.py 192.168.1.0/24 --network-scan --discovery all --aggressive
```

4. **Selective Scanning**
```bash
# Web-only scan (skip network scanning)
python3 reconraptor.py target.com --skip-network

# Skip banner and disclaimer
python3 reconraptor.py target.com --no-banner
```

### Additional Options

```bash
# Set custom output directory
python3 reconraptor.py target.com --output /path/to/reports

# Set custom timeout
python3 reconraptor.py target.com --timeout 30

# Set number of threads
python3 reconraptor.py target.com --threads 20
```

## Network Scanning Features

The network scanning module includes:

1. **Host Discovery Methods**
   - ICMP Echo (ping)
   - ARP Scanning
   - TCP SYN/ACK Ping
   - UDP Ping
   - Comprehensive (all methods)

2. **Network Range Support**
   - CIDR notation (e.g., 192.168.1.0/24)
   - IP ranges (e.g., 192.168.1.1-254)
   - Single IP addresses

3. **Host Information**
   - IP address
   - Hostname resolution
   - MAC address detection
   - Vendor identification
   - Status (up/down)

4. **Service Detection**
   - Accurate service version detection
   - Product and version information
   - CPE (Common Platform Enumeration) data

5. **OS Detection**
   - Operating system fingerprinting
   - OS version detection
   - Accuracy ratings

6. **NSE Script Scanning**
   - Default scripts
   - Vulnerability detection
   - Authentication testing
   - SSL/TLS analysis
   - Banner grabbing

7. **Aggressive Scanning**
   - Comprehensive host enumeration
   - Advanced service probing
   - More detailed OS detection
   - Additional NSE scripts

## Report Types

1. **Summary Report**
   - Overview of all scans
   - Key findings and statistics
   - Module execution status

2. **Network Scan Report**
   - Open ports and services
   - OS detection results
   - Service versions
   - Vulnerability findings

3. **Raw Data Export**
   - JSON format
   - Complete scan results
   - Detailed technical information

## Legal Disclaimer

This tool is for educational and authorized penetration testing purposes ONLY. Unauthorized use against systems you don't own or have explicit permission to test is illegal and unethical.

By using ReconRaptor, you agree to:
1. Use it only for legal and authorized testing
2. Not use it for malicious purposes
3. Take full responsibility for your actions

## License

[Insert your chosen license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🚨 Legal Disclaimer

**IMPORTANT:** This tool is intended for **educational purposes and authorized penetration testing only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. By using this tool, you agree to:

- Use it only for legal and authorized testing
- Not use it for malicious purposes
- Take full responsibility for your actions

## 🛠️ Core Features

### 1. Website Information Scanner
- Server headers analysis
- HTTP status checking
- IP address resolution
- Technology stack detection
- Content-Type analysis
- Server software identification

### 2. Directory & File Bruteforcing
- Custom wordlist support
- Threaded scanning for performance
- Status code analysis (200, 301, 302, 403, 404)
- Response size analysis
- Title extraction
- Common directory detection

### 3. Login Brute-Force (Safe Mode)
- Form-based login testing
- Lockout detection
- Rate limiting
- Custom username/password lists
- Session handling
- CSRF token support

### 4. Basic Vulnerability Scanner
- SQL injection detection
- XSS vulnerability checking
- Common misconfigurations
- Security headers analysis
- SSL/TLS configuration checks

### 5. Report Generator
- Structured .txt reports
- Detailed findings documentation
- Timestamp and metadata
- Vulnerability classification
- Recommendations


```

### Troubleshooting

If you encounter the "externally-managed-environment" error:
1. Make sure you've activated the virtual environment (you should see `(.venv)` in your prompt)
2. Verify you're using the correct pip:
```bash
which pip  # Should show path to .venv/bin/pip
```
3. If the error persists, try:
```bash
python -m pip install --user -r requirements.txt
```

### Deactivating the Virtual Environment
When you're done using ReconRaptor, you can deactivate the virtual environment:
```bash
deactivate
```

### Note for Future Use
Always activate the virtual environment before using ReconRaptor:
```bash
cd /path/to/ReconRaptor
source .venv/bin/activate  # For Linux/macOS
# or
.\venv\Scripts\activate  # For Windows
```

## 🚀 Usage Guide

### Basic Usage
```bash
# Method 1: Using the Python module
python -m reconraptor.interface https://example.com

# Method 2: Using the reconraptor.py script
python reconraptor.py https://example.com

# Method 3: Making the script executable
chmod +x reconraptor.py
./reconraptor.py https://example.com
```

### Advanced Usage
```bash
# Full scan with all options
python reconraptor.py https://example.com \
    --wordlist /path/to/wordlist.txt \
    --threads 20 \
    --login-url https://example.com/login \
    --timeout 15 \
    --output ./scan_results

# Skip banner display
python reconraptor.py https://example.com --no-banner

# Show version
python reconraptor.py --version
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `target` | Target URL to scan | Required |
| `--wordlist` | Path to wordlist file | None |
| `--login-url` | Login URL for brute-force testing | None |
| `--threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 10 |
| `--output` | Output directory for reports | ./reports |
| `--no-banner` | Skip banner display | False |
| `--version` | Show version and exit | N/A |

### Example Scenarios

1. Basic website scan:
```bash
python -m reconraptor.interface https://example.com
```

2. Directory brute-forcing:
```bash
python -m reconraptor.interface https://example.com --wordlist /usr/share/wordlists/dirb/common.txt
```

3. Login form testing:
```bash
python -m reconraptor.interface https://example.com --login-url https://example.com/login
```

## 🔧 Configuration

The tool can be configured through:
- Command line arguments
- Environment variables
- Configuration file (coming soon)

## 📝 Report Format

Reports are generated in the following structure:
```
reports/
├── scan_20240101_120000/
│   ├── website_info.txt
│   ├── directories.txt
│   ├── vulnerabilities.txt
│   └── summary.txt
```

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

- This tool is for educational purposes only
- Always obtain proper authorization before testing
- Respect rate limits and system resources
- Do not use against production systems without permission

## 📞 Support

For support, please:
1. Check the [documentation](docs/)
2. Open an issue on GitHub
3. Join our community discussions

---

Made with ❤️ by the ReconRaptor Team 