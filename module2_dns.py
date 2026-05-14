# filename: module2_dns.py
# ============================================================
import os
import time
import socket
import threading
import configparser
import csv
import logging
import unicodedata
from urllib.request import urlopen
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver
import Levenshtein
from chain_of_custody import log_event, hash_network_event

logger = logging.getLogger("BlackBox.Module2_DNS")

CONFIG_PATH = os.path.join(os.getcwd(), "config.ini")
if not os.path.exists(CONFIG_PATH):
    # Fallback to absolute if run from outside
    CONFIG_PATH = "C:\\BLACKBOX\\config.ini"

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

SAFE_DOMAINS = [
    "google.com", "youtube.com", "schoology.com", "netflix.com", 
    "roblox.com", "discord.com", "gmail.com", "outlook.com", 
    "office.com", "zoom.us", "scholar.google.com", "microsoft.com", 
    "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org"
]

MALICIOUS_DOMAINS_FILE = "malicious_domains.txt"

class BlackBoxResolver(BaseResolver):
    def __init__(self, upstream_ip, redirect_ip, typosquat_threshold, trigger_callback):
        self.upstream_ip = upstream_ip
        self.redirect_ip = redirect_ip
        self.typosquat_threshold = int(typosquat_threshold)
        self.trigger_callback = trigger_callback
        self.malicious_domains = set()
        self.load_malicious_domains()

    def load_malicious_domains(self):
        if os.path.exists(MALICIOUS_DOMAINS_FILE):
            with open(MALICIOUS_DOMAINS_FILE, "r", encoding="utf-8") as f:
                self.malicious_domains = set(line.strip().lower() for line in f if line.strip())
            logger.info(f"Loaded {len(self.malicious_domains)} malicious domains.")
        else:
            logger.warning("Malicious domain list not found. Waiting for updater thread.")

    def normalize_domain(self, domain):
        # Unicode normalization (NFKC)
        normalized = unicodedata.normalize('NFKC', domain)
        # Handle dotless i and omicron replacements
        normalized = normalized.replace('ı', 'i').replace('ο', 'o')
        return normalized.lower()

    def check_domain(self, qname):
        """Returns (is_blocked, reason, distance)"""
        raw_domain = str(qname).rstrip('.').lower()
        normalized_domain = self.normalize_domain(raw_domain)

        # 1. Check exact match in safe domains (allow fast)
        if normalized_domain in SAFE_DOMAINS:
            return False, "", 0

        # 2. Check Blacklist
        if normalized_domain in self.malicious_domains:
            return True, "BLACKLIST", 0
        
        # Check subdomains against blacklist (e.g., evil.malware.com)
        parts = normalized_domain.split('.')
        for i in range(len(parts)-1):
            parent = '.'.join(parts[i:])
            if parent in self.malicious_domains:
                return True, "BLACKLIST_SUBDOMAIN", 0

        # 3. Check Typosquatting / Homograph
        for safe in SAFE_DOMAINS:
            dist = Levenshtein.distance(normalized_domain, safe)
            if dist <= self.typosquat_threshold:
                # E.g., g00gle.com vs google.com
                return True, f"TYPOSQUAT (matches {safe})", dist
            
            # Homograph check via IDNA
            try:
                if normalized_domain.encode('idna') != raw_domain.encode('idna'):
                    # It's an IDN, check if it looks like a safe domain after normalization
                    if normalized_domain == safe:
                         return True, f"HOMOGRAPH (matches {safe})", 0
            except:
                pass

        return False, "", 0

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        
        is_blocked, reason, distance = self.check_domain(qname)
        
        if is_blocked:
            logger.warning(f"BLOCKED DNS QUERY: {qname} Reason: {reason}")
            reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A(self.redirect_ip)))
            
            # Log to chain of custody
            evt_hash = hash_network_event(str(qname), self.redirect_ip, str(time.time()))
            log_event("DNS_BLOCK", {
                "domain": str(qname),
                "ip_address": self.redirect_ip,
                "trigger_details": reason,
                "levenshtein_distance": distance,
                "sha256_hash": evt_hash
            })

            # Fire callback to alert module
            if self.trigger_callback:
                self.trigger_callback("DNS_BLOCK", str(qname))

            return reply

        # Forward query to upstream
        try:
            proxy_req = request.send(self.upstream_ip, 53, timeout=3)
            reply = DNSRecord.parse(proxy_req)
        except Exception as e:
            logger.error(f"Upstream DNS failure: {e}")
            reply.header.rcode = getattr(getattr(dnslib, 'RCODE', None), 'SERVFAIL', 2)
            
        return reply

def update_malicious_domains():
    logger.info("Fetching domain blacklists...")
    domains = set()
    
    # URLhaus CSV
    try:
        urlhaus = urlopen("https://urlhaus.abuse.ch/downloads/csv/", timeout=10)
        lines = [line.decode('utf-8') for line in urlhaus.readlines()]
        reader = csv.reader(filter(lambda row: row[0]!='#', lines))
        for row in reader:
            if len(row) > 2:
                url = row[2]
                # Extract domain from URL
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc.split(':')[0]
                    if domain:
                        domains.add(domain.lower())
                except:
                    pass
    except Exception as e:
        logger.error(f"Failed to fetch URLhaus: {e}")

    # StevenBlack hosts
    try:
        sb_hosts = urlopen("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", timeout=10)
        for line in sb_hosts:
            line = line.decode('utf-8').strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                    domains.add(parts[1].lower())
    except Exception as e:
        logger.error(f"Failed to fetch StevenBlack hosts: {e}")

    if domains:
        with open(MALICIOUS_DOMAINS_FILE, "w", encoding="utf-8") as f:
            for d in sorted(domains):
                f.write(d + "\n")
        logger.info(f"Updated blacklist with {len(domains)} domains.")
        return True
    return False

def updater_thread_loop(interval_hours, resolver):
    while True:
        if update_malicious_domains():
            resolver.load_malicious_domains()
        time.sleep(interval_hours * 3600)

class DNSModule:
    def __init__(self, trigger_callback=None):
        self.enabled = config.getboolean('Module2_DNS', 'enable_dns_proxy', fallback=True)
        self.port = config.getint('Module2_DNS', 'dns_listen_port', fallback=53)
        self.upstream = config.get('Module2_DNS', 'upstream_dns_server', fallback='8.8.8.8')
        self.redirect_ip = config.get('Module2_DNS', 'redirect_ip', fallback='127.0.0.1')
        self.threshold = config.getint('Module2_DNS', 'typosquat_levenshtein_threshold', fallback=2)
        self.update_interval = config.getint('Module2_DNS', 'blocklist_update_interval_hours', fallback=24)
        
        self.resolver = BlackBoxResolver(self.upstream, self.redirect_ip, self.threshold, trigger_callback)
        self.server = DNSServer(self.resolver, port=self.port, address="127.0.0.1", tcp=False)
        self.updater_thread = None

    def start(self):
        if not self.enabled:
            logger.info("DNS Proxy is disabled in config.")
            return

        # Start updater thread
        self.updater_thread = threading.Thread(target=updater_thread_loop, args=(self.update_interval, self.resolver), daemon=True)
        self.updater_thread.start()

        # Start DNS server
        logger.info(f"Starting DNS proxy on 127.0.0.1:{self.port} forwarding to {self.upstream}")
        try:
            self.server.start_thread()
        except OSError as e:
            logger.error(f"Failed to bind to port {self.port}. Is another DNS server running? Error: {e}")

    def stop(self):
        if self.server:
            self.server.stop()
            logger.info("DNS proxy stopped.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mod = DNSModule(trigger_callback=lambda event, dom: print(f"Triggered: {event} on {dom}"))
    mod.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mod.stop()
