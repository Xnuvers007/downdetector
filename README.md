# 🔍 DownDetector

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A robust, multi-threaded tool for real-time website monitoring and downtime detection with detailed diagnostics.

## ✨ Features

- **Real-time Website Monitoring**: Continuously check website availability with configurable intervals
- **Multi-threaded Performance**: Efficiently monitor multiple websites simultaneously
- **Intelligent Rate Limiting**: Domain-specific request throttling to avoid IP blocking
- **Smart Retry Logic**: Automatic backoff and retry for intermittent failures
- **Comprehensive IP Resolution**: View both IPv4 and IPv6 addresses for monitored domains
- **CDN Detection**: Automatically identify if websites are behind Cloudflare, Akamai, Fastly, AWS, or other CDNs
- **DNS Analysis**: Perform reverse DNS lookups for deeper diagnostics
- **SSL Certificate Validation**: Verify SSL certificates for HTTPS websites
- **Persistent Configuration**: Save monitoring settings between sessions
- **Detailed Logging**: Track uptime/downtime events with timestamps and error details

## 📋 Requirements

- Python 3.6+
- Required packages: `requests`

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Xnuvers007/downdetector.git
cd downdetector

# Install dependencies
pip install requests
```

## 💻 Usage

Run the script using Python:

```bash
python downdetector.py
```

### Configuration

On first run, you will be prompted to:

1. Enter one or more websites to monitor (comma-separated)
2. Set the check interval (in seconds, minimum 10)

For subsequent runs, you can choose to use previously configured websites or enter new ones.

### Example Output

```
==================================================
🔍 ADVANCED WEBSITE DOWNDETECTOR 🔍
==================================================

Monitoring the following URLs:
  Hostname: example.com
  IPv4 Addresses:
    • 93.184.216.34 - example.com
  IPv6 Addresses:
    • 2606:2800:220:1:248:1893:25c8:1946
  
  - https://example.com

  Hostname: cloudflare.com
  IPv4 Addresses:
    • 104.16.124.96 - No reverse DNS record
    • 104.16.123.96 - No reverse DNS record
  CDN Detection:
    • Website appears to be behind: cloudflare
    • The IP addresses found may belong to the CDN, not the origin server
  
  - https://cloudflare.com

Check interval: Every 60 seconds

Press Ctrl+C to stop monitoring.

[UP] https://example.com - UP (HTTP 200, 423.45ms)
[UP] https://cloudflare.com - UP (HTTP 200, 215.78ms)
```

## 📊 Status Indicators

- `[UP]` - Website responding with successful HTTP status code (200-399)
- `[DOWN]` - Website unreachable or responding with error code (400+)
- `[UNKNOWN]` - Status could not be determined

## 🔒 Security Features

- URL sanitization and validation
- Protection against private IP address scanning
- Configurable timeouts and retry limits
- Randomized User-Agent headers

## 📝 Logging

The tool logs all events to both console and a `downdetector.log` file, which can be used for historical analysis and troubleshooting.

## 🛠️ Advanced Configuration

Edit the following constants in the script to customize behavior:

- `MAX_WORKERS`: Maximum number of concurrent threads (default: 10)
- `MAX_RETRIES`: Maximum retry attempts for failed requests (default: 3)
- `DEFAULT_TIMEOUT`: Request timeout in seconds (default: 10)
- `RATE_LIMIT_PER_DOMAIN`: Time between requests to the same domain (default: 10)
- `DEFAULT_CHECK_INTERVAL`: Default website check interval (default: 60)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

If you encounter any problems or have suggestions, please open an issue on the project's GitHub.
