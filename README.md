# 🔍 Downdetector

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A powerful, multithreaded tool for monitoring website availability and detecting downtime with advanced features like IP resolution, CDN detection, and SSL validation.

## ✨ Features

- **Real-time Website Monitoring** - Continuously check the status of multiple websites
- **Intelligent IP Resolution** - Resolve both IPv4 and IPv6 addresses for monitored websites
- **CDN Detection** - Automatically identify if websites are behind popular CDNs (Cloudflare, Akamai, etc.)
- **SSL Certificate Validation** - Verify SSL certificates for secure websites
- **Reverse DNS Lookup** - Get hostname information for IP addresses
- **Configurable Check Intervals** - Customize how frequently sites are checked
- **Rate Limiting** - Smart rate limiting to prevent overloading servers
- **Detailed Logging** - Comprehensive logging of all activity and errors
- **Persistent Configuration** - Save your monitoring setup between sessions
- **Multi-threaded Performance** - Efficiently monitor multiple sites simultaneously

## 📋 Requirements

- Python 3.6 or higher
- Required Python packages:
  - requests
  - typing
  - urllib3

## 🚀 Installation

1. Clone this repository or download the script:

```bash
git clone https://github.com/xnuvers007/downdetector.git
cd downdetector
```

2. Install the required dependencies:

```bash
pip install requests urllib3
```

3. Run the script:

```bash
python downdetector.py
```

## 💻 Usage

1. Start the script and enter websites to monitor (comma-separated):

```
🔍 ADVANCED WEBSITE DOWNDETECTOR 🔍
==================================================
Developed by: xnuvers007
Version: 2.0.0 - 2025
==================================================

Enter website(s) to monitor (comma separated): example.com, github.com, google.com
```

2. Set your preferred check interval (in seconds):

```
Check interval in seconds (default: 60, minimum: 10): 30
```

3. Monitor the results:

```
Monitoring started...
==================================================

Monitoring the following URLs:
Resolving IP addresses...
Done! (1.25s)

Hostname: example.com
IPv4 Addresses:
  • 93.184.216.34 - No reverse DNS record

Hostname: github.com
IPv4 Addresses:
  • 140.82.121.3 - lb-140-82-121-3-fra.github.com
CDN Detection:
  • Website appears to be behind: Fastly
  • The IP addresses found may belong to the CDN, not the origin server

[UP] example.com - UP (HTTP 200, 324.45ms)
[UP] github.com - UP (HTTP 200, 156.78ms)
[UP] google.com - UP (HTTP 200, 89.12ms)
```

4. Press `Ctrl+C` to stop monitoring.

## ⚙️ Configuration

The tool creates a configuration file (`downdetector_config.json`) that stores:
- List of monitored URLs
- Check interval settings
- Last update timestamp

This allows you to easily resume monitoring with the same settings.

## 📊 Technical Details

### Domain Safety Checks

The tool performs various safety checks to prevent monitoring of:
- Localhost addresses
- Private network addresses (10.x.x.x, 192.168.x.x, etc.)
- Link-local addresses
- Other potentially unsafe domains

### CDN Detection

Identifies websites behind common CDNs including:
- Cloudflare
- Akamai
- Fastly
- AWS CloudFront

### HTTP Request Handling

- Configurable retries with exponential backoff
- Proper user agent rotation
- Connection pooling for efficiency
- Automatic handling of redirects
- SSL certificate validation

## 📝 License

[MIT License](LICENSE)

## 👨‍💻 Author

Developed by [Xnuvers007](https://github.com/xnuvers007)

## Open Issue

[Click this](https://github.com/Xnuvers007/downdetector/issues/new/choose)
---

*Note: This tool is for educational and informational purposes only. Please use responsibly and respect website terms of service and rate limits.*
