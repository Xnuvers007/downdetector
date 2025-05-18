import requests, time, re, os, json, threading, queue, logging, socket, ssl, base64, hashlib
from datetime import datetime
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

from typing import Dict, List, Optional, Tuple, Set

_signature = "WG51dmVyczAwN19XZWJzaXRlRGV0ZWN0b3JfRm9sbG93TVlHSVRIVUJfaHR0cHM6Ly9naXRodWIuY29tL3hudXZlcnMwMDc="
_auth_hash = "e259c0804ce6c1449034cf8f9c650e78"

def _verify_author_integrity():
    original_author = base64.b64decode(_signature).decode('utf-8')
    computed_hash = hashlib.md5(original_author.replace("_", "").lower().encode()).hexdigest()
    if _auth_hash != computed_hash:
        logger.warning("Author attribution modified. Please respect original attribution.")
    return original_author.split("_")[0]

def _create_attribution_file():
    attribution_file = ".downdetector_attribution"
    if not os.path.exists(attribution_file):
        try:
            with open(attribution_file, "w") as f:
                f.write(f"Advanced Website Downdetector\n")
                f.write(f"Created by: {_verify_author_integrity()}\n")
                f.write(f"Copyright © {datetime.now().year}\n")
        except Exception:
            pass

_create_attribution_file()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("downdetector.log")],
)
logger = logging.getLogger("downdetector")
MAX_WORKERS = 10
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.5
DEFAULT_TIMEOUT = 20
RATE_LIMIT_PER_DOMAIN = 10
DEFAULT_CHECK_INTERVAL = 60
CONFIG_FILE = "downdetector_config.json"
URL_REGEX = re.compile(
    r"^(https?:\/\/)?"
    r"([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    r"(\/[a-zA-Z0-9_.~!*\'();:@&=+$,\/?%#[]-]*)?"
    r"$",
    re.IGNORECASE,
)

author = _verify_author_integrity()
logger.info(f"Author: {author}")
logger.info("Advanced Website Downdetector started.")

class RateLimiter:
    def __init__(self):
        self.last_request_time: Dict[str, float] = {}
        self.lock = threading.Lock()

    def wait_if_needed(self, domain: str) -> None:
        with self.lock:
            current_time = time.time()
            if domain in self.last_request_time:
                elapsed = current_time - self.last_request_time[domain]
                if elapsed < RATE_LIMIT_PER_DOMAIN:
                    time_to_wait = RATE_LIMIT_PER_DOMAIN - elapsed
                    time.sleep(time_to_wait)
            self.last_request_time[domain] = time.time()

class DownDetector:
    def __init__(self, check_interval: int = DEFAULT_CHECK_INTERVAL):
        self._author = _verify_author_integrity()
        self.check_interval = check_interval
        self.urls: Set[str] = set()
        self.history: Dict[str, List[Dict]] = {}
        self.session = self._create_session()
        self.rate_limiter = RateLimiter()
        self.running = False
        self.worker_queue = queue.Queue()
        self.workers: List[threading.Thread] = []

    def resolve_ip_address(self, url: str) -> Dict:
        result = {
            "url": url,
            "hostname": "",
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "is_cdn": False,
            "dns_info": {},
            "error": None,
        }
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            result["hostname"] = hostname

            socket.setdefaulttimeout(DEFAULT_TIMEOUT)

            try:
                ipv4_info = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
                result["ipv4_addresses"] = list(set(info[4][0] for info in ipv4_info))
            except (socket.gaierror, socket.timeout) as e:
                result["ipv4_addresses"] = []

            try:
                ipv6_info = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
                result["ipv6_addresses"] = list(set(info[4][0] for info in ipv6_info))
            except (socket.gaierror, socket.timeout):
                result["ipv6_addresses"] = []
            cdn_patterns = {
                "cloudflare": [
                    "104.16.",
                    "104.17.",
                    "104.18.",
                    "104.19.",
                    "172.64.",
                    "173.245.",
                    "108.162.",
                    "173.245.48.",
                    "103.21.244.",
                    "103.22.200.",
                    "103.31.4.",
                    "141.101.64.",
                    "108.162.192.",
                    "190.93.240.",
                    "188.114.96.",
                    "197.234.240.",
                    "198.41.128.",
                    "162.158.",
                    "104.16.",
                    "104.24.",
                    "172.64.",
                    "131.0.72.",
                ],
                "akamai": ["23.72.", "23.73.", "104.64.", "184.24."],
                "fastly": ["151.101.", "199.232."],
                "aws": ["13.32.", "13.33.", "13.35.", "143.204."],
            }
            for ip in result["ipv4_addresses"]:
                for cdn, patterns in cdn_patterns.items():
                    if any(ip.startswith(pattern) for pattern in patterns):
                        result["is_cdn"] = True
                        if "cdn_providers" not in result:
                            result["cdn_providers"] = []
                        result["cdn_providers"].append(cdn)
                        break
            for ip in result["ipv4_addresses"]:
                try:
                    hostname_info = socket.gethostbyaddr(ip)
                    result["dns_info"][ip] = hostname_info[0]
                except (socket.herror, socket.gaierror):
                    result["dns_info"][ip] = "No reverse DNS record"
            logger.info(
                f"Successfully resolved {url} to {', '.join(result['ipv4_addresses'])}"
            )
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Failed to resolve {url}: {e}")
        return result

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        headers_list = [
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Pragma": "no-cache",
                "Cache-Control": "max-age=0",
            },
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            },
            {
                # empty
            },
        ]
        combined_headers = headers_list[0]
        combined_headers.update(headers_list[1])
        combined_headers.update(headers_list[2])
        session.headers.update(combined_headers)
        return session

    def sanitize_urls(self, input_string: str) -> List[str]:
        raw_urls = re.split(r"[,\s]+", input_string.strip())
        clean_urls = set()
        for raw in raw_urls:
            if not raw:
                continue
            if not raw.startswith(("http://", "https://")):
                raw = "https://" + raw
            if not URL_REGEX.match(raw):
                logger.warning(f"Invalid URL skipped: {raw}")
                continue
            parsed = urlparse(raw)
            domain = parsed.netloc.lower()
            if self._is_unsafe_domain(domain):
                logger.warning(f"Potentially unsafe domain skipped: {domain}")
                continue
            if domain.endswith(".") or "." not in domain:
                logger.warning(f"Invalid domain skipped: {domain}")
                continue
            full_url = f"{parsed.scheme}://{domain}"
            clean_urls.add(full_url)
        return list(clean_urls)

    def _is_unsafe_domain(self, domain: str) -> bool:
        unsafe_patterns = [
            r"^localhost$",
            r"^127\.\d+\.\d+\.\d+$",
            r"^10\.\d+\.\d+\.\d+$",
            r"^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$",
            r"^192\.168\.\d+\.\d+$",
            r"^169\.254\.\d+\.\d+$",
            r"^::1$",
            r"^fc00:",
            r"^fd00:",
        ]
        for pattern in unsafe_patterns:
            if re.match(pattern, domain):
                return True
        try:
            ip = socket.gethostbyname(domain)
            for pattern in unsafe_patterns:
                if re.match(pattern, ip):
                    return True
        except socket.gaierror:
            pass
        return False

    def check_status(self, url: str) -> Dict:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        self.rate_limiter.wait_if_needed(domain)
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "status_code": None,
            "response_time": None,
            "error": None,
            "ssl_valid": None,
        }
        start_time = time.time()
        try:
            if url.startswith("https://"):
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection(
                        (domain, 443), timeout=DEFAULT_TIMEOUT
                    ) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            result["ssl_valid"] = True
                except (socket.error, ssl.SSLError, OSError) as e:
                    result["ssl_valid"] = False
                    result["error"] = f"SSL Error: {str(e)}"
            response = self.session.get(
                url, timeout=DEFAULT_TIMEOUT, allow_redirects=True
            )
            result["status_code"] = response.status_code
            result["response_time"] = round((time.time() - start_time) * 1000, 2)
            if 200 <= response.status_code < 400:
                result["status"] = "up"
            else:
                result["status"] = "down"
        except requests.exceptions.RequestException as e:
            result["status"] = "down"
            result["error"] = str(e)
            result["response_time"] = round((time.time() - start_time) * 1000, 2)
        if url not in self.history:
            self.history[url] = []
        self.history[url].append(result)
        if len(self.history[url]) > 100:
            self.history[url].pop(0)
        return result

    def worker(self) -> None:
        while self.running:
            try:
                url = self.worker_queue.get(timeout=1)
                result = self.check_status(url)
                self._display_status(result)
                self.worker_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")

    def _display_status(self, result: Dict) -> None:
        # status_icons = {"up": "✅", "down": "❌", "unknown": "❓"}
        status_icons = {"up": "[UP]", "down": "[DOWN]", "unknown": "[UNKNOWN]"}
        icon = status_icons.get(result["status"], "❓")
        if result["status"] == "up":
            logger.info(
                f"{icon} {result['url']} - UP (HTTP {result['status_code']}, {result['response_time']}ms)"
            )
        else:
            error_msg = f" - {result['error']}" if result["error"] else ""
            logger.warning(f"{icon} {result['url']} - DOWN{error_msg}")

    def start_monitoring(self) -> None:
        if not self.urls:
            logger.error("No valid URLs to monitor. Exiting.")
            return
        self.running = True
        for _ in range(min(MAX_WORKERS, len(self.urls))):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self.workers.append(t)
        logger.info(
            f"Started monitoring {len(self.urls)} URLs with check interval of {self.check_interval}s"
        )
        try:
            while self.running:
                for url in self.urls:
                    self.worker_queue.put(url)
                self.worker_queue.join()
                self.save_config()
                time.sleep(self.check_interval)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user.")
        finally:
            self.running = False
            self.save_config()

    def save_config(self) -> None:
        config = {
            "urls": list(self.urls),
            "check_interval": self.check_interval,
            "last_updated": datetime.now().isoformat(),
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    def load_config(self) -> bool:
        if not os.path.exists(CONFIG_FILE):
            return False
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            self.urls = set(config.get("urls", []))
            self.check_interval = config.get("check_interval", DEFAULT_CHECK_INTERVAL)
            logger.info(f"Loaded configuration with {len(self.urls)} URLs")
            return True
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False


def main():
    print("\n" * 3)
    print("=" * 50)
    print("🔍 ADVANCED WEBSITE DOWNDETECTOR 🔍")
    print("=" * 50)
    print(f"Developed by: {_verify_author_integrity()}")
    print(f"Version: 2.0.0 - {datetime.now().year}")
    print("=" * 50)

    detector = DownDetector()

    if detector.load_config():
        print(f"Loaded {len(detector.urls)} URLs from previous configuration.")
        try:
            use_existing = input("Use existing URLs? (y/n): ").strip().lower()
        except KeyboardInterrupt:
            print("\nExiting...")
            return

        if use_existing == "y":
            print("Using existing URLs.")
            if detector.urls:
                print("Existing URLs:")
                for url in sorted(detector.urls):
                    print(f"  - {url}")
                try:
                    clear_existing = input("Clear existing URLs? (y/n): ").strip().lower()
                except KeyboardInterrupt:
                    print("\nExiting...")
                    return

                if clear_existing == "y":
                    detector.urls = set()
                    print("Existing URLs cleared.")
                else:
                    print("Keeping existing URLs.")
        else:
            print("Not using existing URLs.")
            detector.urls = set()

    try:
        urls_input = input("Enter website(s) to monitor (comma separated/empty if dont want add new): ").strip()
    except KeyboardInterrupt:
        print("\nExiting...")
        return

    if urls_input:
        new_urls = detector.sanitize_urls(urls_input)
        detector.urls.update(new_urls)
        print(f"Appending {len(new_urls)} new URL(s) to existing list.")

    try:
        interval_input = input(f"Check interval in seconds (default: {DEFAULT_CHECK_INTERVAL}, minimum: 10): ").strip()
        if interval_input:
            detector.check_interval = max(10, int(interval_input))
    except ValueError:
        print(f"Invalid interval. Using default ({DEFAULT_CHECK_INTERVAL}s).")
    except KeyboardInterrupt:
        print("\nExiting...")
        return

    if not detector.urls:
        print("No valid URLs provided. Exiting.")
        return

    print("\n" + "=" * 50)
    print("Monitoring started...")
    print("=" * 50)

    print("\nMonitoring the following URLs:")
    print("Resolving IP addresses...", end="\n")
    cdn_summary = {}

    start_time = time.time()
    results = {}

    def resolve_ip_for_url(url):
        try:
            return url, detector.resolve_ip_address(url)
        except Exception as e:
            logger.error(f"Error resolving {url}: {str(e)}")
            return url, {"error": str(e)}
    
    with ThreadPoolExecutor(max_workers=min(10, len(detector.urls))) as executor:
        future_to_url = {executor.submit(resolve_ip_for_url, url): url for url in sorted(detector.urls)}
        
        for i, future in enumerate(as_completed(future_to_url)):
            url = future_to_url[future]
            try:
                _, ip_info = future.result()
                results[url] = ip_info
                print(".", end="", flush=True)
            except Exception as e:
                results[url] = {"error": str(e)}
                print("x", end="", flush=True)
    
    print(f"\nDone! ({time.time() - start_time:.2f}s)")
    
    for url in sorted(detector.urls):
        ip_info = results.get(url, {"error": "Resolution failed"})
        
        if ip_info.get("error"):
            print(f"\n  Error resolving {url}: {ip_info['error']}")
            continue

        print(f"\n  Hostname: {ip_info.get('hostname', url)}")

        if ip_info.get("ipv4_addresses"):
            print("  IPv4 Addresses:")
            for ip in ip_info["ipv4_addresses"]:
                dns_info = ip_info.get("dns_info", {}).get(ip, "No reverse DNS record")
                print(f"    • {ip} - {dns_info}")
        else:
            print("  No IPv4 addresses found")

        if ip_info.get("ipv6_addresses"):
            print("  IPv6 Addresses:")
            for ip in ip_info["ipv6_addresses"]:
                print(f"    • {ip}")

        if ip_info.get("is_cdn"):
            cdns = ip_info.get("cdn_providers", ["Unknown CDN"])
            print("  CDN Detection:")
            print(f"    • Website appears to be behind: {', '.join(cdns)}")
            print("    • The IP addresses found may belong to the CDN, not the origin server")
            for cdn in cdns:
                ip_addresses = ip_info.get("ipv4_addresses", []) or ip_info.get("ipv6_addresses", [])
                cdn_summary.setdefault(cdn, []).append((url, ip_addresses))

        print(f"\n  - {url}")

    print(f"\nCheck interval: Every {detector.check_interval} seconds")
    print("\nPress Ctrl+C to stop monitoring.\n")

    if cdn_summary:
        print("=" * 50)
        print("CDN Summary:")

        for cdn, urls in sorted(cdn_summary.items()):
            print(f"  {cdn.lower()}:")

            sorted_urls = sorted(urls, key=lambda x: x[0])

            for u, ip_addresses in sorted_urls:
                sorted_ips = sorted(ip_addresses)
                
                if sorted_ips:
                    print(f"    • {u} - {', '.join(sorted_ips)}")
                else:
                    print(f"    • {u} - No IPv4 addresses found")
        print("=" * 50)

    detector.start_monitoring()

if __name__ == "__main__":
    main()
