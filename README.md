# 🔍 Advanced Bug Bounty Reconnaissance Tool

A comprehensive, automated bug bounty reconnaissance and vulnerability scanning tool that combines multiple industry-standard tools into one powerful framework.

## 🌟 Features

### 📍 Reconnaissance
- **Subdomain Enumeration** - Automated subdomain discovery using multiple sources
- **Live Subdomain Filtering** - Identifies active subdomains with port scanning
- **URL Collection** - Passive URL gathering from multiple sources (Wayback Machine, Common Crawl, etc.)
- **Technology Stack Detection** - Identifies web technologies and frameworks
- **DNS Record Analysis** - Comprehensive DNS enumeration
- **SSL Certificate Analysis** - SSL/TLS configuration checking

### 🔒 Vulnerability Assessment
- **XSS Detection** - Cross-Site Scripting vulnerability scanning
- **SQL Injection Testing** - Automated SQLi detection
- **Local File Inclusion (LFI)** - LFI vulnerability assessment  
- **CORS Misconfiguration** - Cross-Origin Resource Sharing issues
- **Subdomain Takeover** - Dangling subdomain detection
- **Directory Bruteforcing** - Hidden directory and file discovery
- **Parameter Discovery** - Hidden parameter enumeration

### 📁 Sensitive Data Discovery
- **Sensitive File Detection** - Automated discovery of exposed sensitive files
- **API Key Extraction** - JavaScript file analysis for exposed API keys
- **AWS S3 Bucket Discovery** - S3 bucket enumeration and testing
- **Git Repository Detection** - Exposed .git directory discovery
- **Information Disclosure** - Google dorking and passive reconnaissance

### 🔧 Specialized Scanning
- **WordPress Security Scan** - Comprehensive WordPress vulnerability assessment
- **JavaScript Analysis** - JS file hunting and analysis
- **Port Scanning** - Network service discovery
- **Content-Type Analysis** - HTTP response analysis

### 📊 Reporting & Management
- **Web Dashboard** - Real-time results visualization
- **JSON Export** - Structured data export
- **Multi-threading** - Concurrent scanning for faster results
- **Progress Tracking** - Real-time scan progress monitoring

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Linux/macOS (Recommended)
- Root/sudo access (for some tools)

### Required Tools
This tool integrates with the following external tools. Please install them first:

```bash
# Essential tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Additional tools
pip3 install arjun
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/dwisiswant0/urldedupe@latest
go install github.com/KathanP19/Gxss@latest
go install github.com/Emoe/kxss@latest
go install github.com/tomnomnom/qsreplace@latest
go install -v github.com/ffuf/ffuf@latest

# Install tool dependencies
sudo apt-get update
sudo apt-get install nmap masscan sqlmap wpscan
```

### Python Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/advanced-bug-bounty-tool.git
cd advanced-bug-bounty-tool

# Install Python dependencies
pip3 install -r requirements.txt

# Make the script executable
chmod +x bug_bounty_tool.py
```

## 🚀 Usage

### Command Line Interface

```bash
# Basic scan
python3 bug_bounty_tool.py -d example.com

# Full scan with all modules
python3 bug_bounty_tool.py -d example.com --full-scan

# Custom output directory
python3 bug_bounty_tool.py -d example.com -o /path/to/output

# Specific modules only
python3 bug_bounty_tool.py -d example.com --modules subdomain,vulnerability

# With web dashboard
python3 bug_bounty_tool.py -d example.com --web-dashboard

# Threaded scanning (faster)
python3 bug_bounty_tool.py -d example.com --threads 50
```

### Web Dashboard

Start the web interface for real-time monitoring:

```bash
python3 bug_bounty_tool.py -d example.com --web-dashboard --port 5000
```

Then visit `http://localhost:5000` in your browser.

### Command Line Arguments

```
usage: bug_bounty_tool.py [-h] -d DOMAIN [-o OUTPUT] [--modules MODULES] 
                         [--threads THREADS] [--timeout TIMEOUT] 
                         [--web-dashboard] [--port PORT] [--full-scan]
                         [--passive-only] [--aggressive]

Advanced Bug Bounty Reconnaissance Tool

required arguments:
  -d DOMAIN, --domain DOMAIN    Target domain to scan

optional arguments:
  -h, --help                    Show this help message and exit
  -o OUTPUT, --output OUTPUT    Output directory (default: results)
  --modules MODULES             Comma-separated modules to run
  --threads THREADS             Number of threads (default: 20)
  --timeout TIMEOUT             Request timeout in seconds (default: 30)
  --web-dashboard               Start web dashboard
  --port PORT                   Web dashboard port (default: 5000)
  --full-scan                   Run all available modules
  --passive-only                Run only passive reconnaissance
  --aggressive                  Enable aggressive scanning mode
```

## 📋 Available Modules

| Module | Description |
|--------|-------------|
| `subdomain` | Subdomain enumeration and discovery |
| `live_check` | Live subdomain verification |
| `url_collection` | Passive URL gathering |
| `sensitive_files` | Sensitive file discovery |
| `vulnerability` | General vulnerability scanning |
| `xss` | XSS vulnerability testing |
| `sqli` | SQL injection testing |
| `lfi` | Local file inclusion testing |
| `cors` | CORS misconfiguration testing |
| `subdomain_takeover` | Subdomain takeover detection |
| `port_scan` | Network port scanning |
| `directory_bruteforce` | Directory and file bruteforcing |
| `js_analysis` | JavaScript file analysis |
| `parameter_discovery` | Hidden parameter enumeration |
| `wordpress` | WordPress security scanning |
| `aws_s3` | AWS S3 bucket discovery |
| `api_keys` | API key extraction |
| `technology_detection` | Technology stack identification |

## 📁 Output Structure

```
results/
└── example.com/
    ├── subdomains.txt
    ├── live_subdomains.txt
    ├── all_urls.txt
    ├── sensitive_files.txt
    ├── vulnerabilities.json
    ├── xss_results.txt
    ├── sql_injection_results.txt
    ├── port_scan_results.txt
    ├── js_files.txt
    ├── parameters.txt
    ├── cors_issues.txt
    ├── subdomain_takeover.txt
    ├── aws_s3_buckets.txt
    ├── api_keys.txt
    ├── wordpress_scan.txt
    ├── directory_bruteforce.txt
    └── final_report.json
```

## 🔧 Configuration

### Custom Wordlists
Place your custom wordlists in the `wordlists/` directory:
- `wordlists/subdomains.txt`
- `wordlists/directories.txt`
- `wordlists/parameters.txt`
- `wordlists/lfi_payloads.txt`
- `wordlists/xss_payloads.txt`

### API Keys Configuration
Create a `config.json` file for API integrations:

```json
{
    "shodan_api_key": "your_shodan_api_key",
    "virustotal_api_key": "your_virustotal_api_key",
    "github_token": "your_github_token",
    "wpscan_api_key": "your_wpscan_api_key"
}
```

## 🐛 Example Scan Output

```bash
$ python3 bug_bounty_tool.py -d example.com --full-scan

[+] Advanced Bug Bounty Tool v2.0
[+] Target: example.com
[+] Starting comprehensive scan...

[*] Phase 1: Subdomain Enumeration
    ├── Found 127 subdomains
    ├── 89 subdomains are live
    └── 12 potential subdomain takeovers detected

[*] Phase 2: URL Collection & Analysis  
    ├── Collected 2,847 URLs from passive sources
    ├── Found 156 URLs with parameters
    └── Discovered 23 sensitive files

[*] Phase 3: Vulnerability Assessment
    ├── 5 XSS vulnerabilities found
    ├── 2 SQL injection points detected
    ├── 8 LFI vulnerabilities discovered
    ├── 15 CORS misconfigurations found
    └── 3 exposed API keys detected

[*] Phase 4: Infrastructure Analysis
    ├── 1,247 open ports discovered
    ├── 45 interesting directories found
    └── WordPress installation detected (3 vulnerabilities)

[+] Scan completed in 45 minutes
[+] Results saved to: results/example.com/
[+] Web dashboard: http://localhost:5000
```

## 🛡️ Ethical Usage

This tool is designed for:
- **Authorized security testing** on systems you own
- **Bug bounty programs** with proper scope
- **Educational purposes** in controlled environments
- **Red team exercises** with explicit permission

**⚠️ Important:** Always ensure you have proper authorization before scanning any target. Unauthorized scanning may violate laws and terms of service.

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📈 Roadmap

- [ ] **Machine Learning Integration** - AI-powered vulnerability detection
- [ ] **API Fuzzing Module** - Automated API security testing
- [ ] **Mobile App Analysis** - Android/iOS security assessment
- [ ] **Cloud Security Module** - AWS/Azure/GCP security scanning
- [ ] **CI/CD Integration** - Jenkins/GitHub Actions support
- [ ] **Custom Plugin System** - Community-driven extensions
- [ ] **Advanced Reporting** - PDF/HTML report generation
- [ ] **Collaboration Features** - Team-based scanning

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) - For amazing reconnaissance tools
- [OWASP](https://owasp.org/) - For security testing methodologies  
- [SecLists](https://github.com/danielmiessler/SecLists) - For comprehensive wordlists
- Bug bounty community - For continuous inspiration and feedback

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/advanced-bug-bounty-tool/issues)

## ⭐ Show Your Support

If this tool helped you in your bug bounty journey, please give it a ⭐ star on GitHub!

---
**Made with ❤️ by [Dumindu] for the Bug Bounty Community**
