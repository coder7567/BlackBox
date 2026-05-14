import csv
import io
import logging
import os
import platform
import re
import socket
import socketserver
import threading
import time
import unicodedata
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
try:
    import scapy
except Exception:
    scapy = None
from dnslib import DNSRecord, QTYPE, RR, A
from Levenshtein import distance as levenshtein_distance

from chain_of_custody import ChainOfCustodyLogger, program_data_root

logger = logging.getLogger("blackbox.dns")
if scapy is not None:
    logger.info("scapy packet engine available for advanced diagnostics.")

SAFE_DOMAINS = [
    "google.com",
    "youtube.com",
    "schoology.com",
    "netflix.com",
    "roblox.com",
    "discord.com",
    "gmail.com",
    "outlook.com",
    "office.com",
    "zoom.us",
    "scholar.google.com",
    "microsoft.com",
    "github.com",
    "stackoverflow.com",
    "reddit.com",
    "wikipedia.org",
]


def hosts_path() -> Path:
    if platform.system() == "Windows":
        return Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def backup_hosts_if_needed() -> None:
    hp = hosts_path()
    if not hp.exists():
        return
    backup = hp.with_suffix(hp.suffix + ".backup")
    if backup.exists():
        return
    try:
        data = hp.read_text(encoding="utf-8", errors="ignore")
        backup.write_text(data, encoding="utf-8")
        logger.info("Backed up hosts file to %s", backup)
    except PermissionError:
        logger.warning("Could not backup hosts (permission denied).")


def append_blackbox_marker_hosts(domains: Set[str], redirect_ip: str) -> None:
    hp = hosts_path()
    marker_begin = "# BEGIN BLACKBOX SINKHOLE"
    marker_end = "# END BLACKBOX SINKHOLE"
    try:
        text = hp.read_text(encoding="utf-8", errors="ignore")
    except PermissionError:
        logger.warning("Cannot read hosts for marker update.")
        return
    if marker_begin in text:
        before, _, rest = text.partition(marker_begin)
        _, _, after = rest.partition(marker_end)
        core = after
    else:
        before = text
        core = ""
    lines = [marker_begin, f"# updated {int(time.time())}"]
    for d in sorted(domains):
        lines.append(f"{redirect_ip} {d}")
    lines.append(marker_end)
    new_text = before.rstrip() + "\n\n" + "\n".join(lines) + "\n" + core.lstrip()
    try:
        hp.write_text(new_text, encoding="utf-8")
    except PermissionError:
        logger.warning("Cannot write hosts marker (run as administrator for full sinkhole).")


def normalize_domain_label(label: str) -> str:
    lowered = label.strip().lower().rstrip(".")
    nfkc = unicodedata.normalize("NFKC", lowered)
    table = str.maketrans({"ı": "i", "ο": "o", "а": "a", "е": "e", "р": "p", "с": "c", "х": "x"})
    return nfkc.translate(table)


def is_punycode_homograph(domain: str) -> bool:
    if "xn--" in domain.lower():
        return True
    return False


def typosquat_reason(domain: str, threshold: int) -> Tuple[bool, str, int]:
    nd = normalize_domain_label(domain)
    best = 999
    for safe in SAFE_DOMAINS:
        d = levenshtein_distance(nd, safe)
        best = min(best, d)
        if d <= threshold:
            return True, f"typosquat_vs_{safe}", d
    if is_punycode_homograph(nd):
        return True, "homograph_punycode", best
    if nd != unicodedata.normalize("NFKC", domain.lower().rstrip(".")):
        return True, "homograph_unicode_normalization", best
    return False, "", best


class BlocklistStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.malicious_path = self.data_dir / "malicious_domains.txt"
        self._domains: Set[str] = set()
        self._lock = threading.Lock()

    def load_disk(self) -> None:
        if self.malicious_path.exists():
            with open(self.malicious_path, "r", encoding="utf-8") as f:
                with self._lock:
                    self._domains = {line.strip().lower() for line in f if line.strip()}

    def merge(self, new_domains: Set[str]) -> None:
        with self._lock:
            self._domains |= {d.lower().rstrip(".") for d in new_domains}
            tmp = sorted(self._domains)
        with open(self.malicious_path, "w", encoding="utf-8") as f:
            for d in tmp:
                f.write(d + "\n")

    def contains(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        with self._lock:
            return d in self._domains

    def count(self) -> int:
        with self._lock:
            return len(self._domains)

    def snapshot(self) -> Set[str]:
        with self._lock:
            return set(self._domains)


def fetch_urlhaus_domains(url: str) -> Set[str]:
    out: Set[str] = set()
    try:
        resp = requests.get(url, timeout=120)
        resp.raise_for_status()
        reader = csv.reader(io.StringIO(resp.text))
        header = next(reader, None)
        if not header:
            return out
        lower = [h.lower() for h in header]
        url_idx = lower.index("url") if "url" in lower else None
        if url_idx is None:
            return out
        for row in reader:
            if not row or url_idx >= len(row):
                continue
            u = row[url_idx].strip()
            if not u:
                continue
            if not u.startswith("http"):
                u = "http://" + u
            netloc = urlparse(u).hostname
            if netloc:
                out.add(netloc.lower())
    except Exception as exc:
        logger.warning("URLhaus fetch failed: %s", exc)
    return out


def fetch_stevenblack_domains(url: str) -> Set[str]:
    out: Set[str] = set()
    try:
        resp = requests.get(url, timeout=120)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[0]):
                host = parts[1].lower()
                if host and host not in ("localhost",):
                    out.add(host.rstrip("."))
    except Exception as exc:
        logger.warning("StevenBlack fetch failed: %s", exc)
    return out


def forward_dns(data: bytes, upstream: str, timeout: float = 4.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(data, (upstream, 53))
        pkt, _ = sock.recvfrom(65535)
        return pkt
    finally:
        sock.close()


class BlackBoxUDPHandler(socketserver.BaseRequestHandler):
    server: "ThreadedDNServer"

    def handle(self) -> None:
        data = self.request
        client = self.client_address
        sock = self.server.socket
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return
        q = request.q
        qname = str(q.qname).rstrip(".").lower()
        block, reason, lev_dist, redirect_ip = self.server.classifier.classify(qname)
        if block:
            client_ip = client[0] if isinstance(client, tuple) else str(client)
            self.server.on_block(qname, reason, lev_dist, client_ip)
            reply = request.reply()
            reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(redirect_ip), ttl=60))
            sock.sendto(reply.pack(), client)
            return
        try:
            resp = forward_dns(data, self.server.upstream)
            sock.sendto(resp, client)
        except Exception as exc:
            logger.warning("Upstream DNS failure for %s: %s", qname, exc)


class DNSClassifier:
    def __init__(self, store: BlocklistStore, threshold: int, redirect_ip: str) -> None:
        self.store = store
        self.threshold = threshold
        self.redirect_ip = redirect_ip

    def classify(self, qname: str) -> Tuple[bool, str, int, str]:
        if self.store.contains(qname):
            return True, "blacklist", 0, self.redirect_ip
        tys, reason, dist = typosquat_reason(qname, self.threshold)
        if tys:
            return True, reason, dist, self.redirect_ip
        return False, "", 0, self.redirect_ip


class ThreadedDNServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(
        self,
        addr: Tuple[str, int],
        handler,
        upstream: str,
        classifier: DNSClassifier,
        on_block: Callable[[str, str, int, str], None],
    ) -> None:
        super().__init__(addr, handler)
        self.upstream = upstream
        self.classifier = classifier
        self.on_block = on_block


def start_blocklist_updater(
    store: BlocklistStore,
    urlhaus_url: str,
    stevenblack_url: str,
    interval_hours: int,
    stop_event: threading.Event,
    redirect_ip: str,
    fallback_hosts: bool,
) -> threading.Thread:
    def _loop() -> None:
        while not stop_event.is_set():
            domains: Set[str] = set()
            domains |= fetch_urlhaus_domains(urlhaus_url)
            domains |= fetch_stevenblack_domains(stevenblack_url)
            if domains:
                store.merge(domains)
                logger.info("Blocklist updated: %s domains", store.count())
            if fallback_hosts and domains:
                append_blackbox_marker_hosts(domains, redirect_ip)
            for _ in range(max(1, interval_hours * 3600)):
                if stop_event.wait(1):
                    break

    t = threading.Thread(target=_loop, name="blocklist-updater", daemon=True)
    t.start()
    return t


def log_dns_block(data_dir: Path, domain: str, reason: str, lev: int) -> None:
    logf = data_dir / "dns_blocklog.csv"
    header_needed = not logf.exists()
    with open(logf, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if header_needed:
            w.writerow(["timestamp", "domain", "reason", "levenshtein"])
        w.writerow([time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), domain, reason, lev])


class DomainRepeatTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: Dict[str, List[float]] = {}

    def record(self, domain: str) -> int:
        now = time.monotonic()
        window = 300.0
        with self._lock:
            arr = self._hits.setdefault(domain, [])
            arr.append(now)
            self._hits[domain] = [t for t in arr if now - t <= window]
            return len(self._hits[domain])


def run_dns_server(
    cfg,
    coc: ChainOfCustodyLogger,
    on_dns_block: Callable[[str, str, int], None],
    repeat_tracker: DomainRepeatTracker,
    stop_event: threading.Event,
) -> Optional[ThreadedDNServer]:
    data_dir = program_data_root()
    data_dir.mkdir(parents=True, exist_ok=True)
    store = BlocklistStore(data_dir)
    store.load_disk()
    upstream = cfg.get("Module2_DNS", "upstream_dns_server", fallback="8.8.8.8")
    port = int(cfg.get("Module2_DNS", "dns_listen_port", fallback="53"))
    threshold = int(cfg.get("Module2_DNS", "typosquat_levenshtein_threshold", fallback="2"))
    redirect_ip = cfg.get("Module2_DNS", "redirect_ip", fallback="127.0.0.1")
    urlhaus = cfg.get("Module2_DNS", "urlhaus_csv_url", fallback="https://urlhaus.abuse.ch/downloads/csv/")
    steven = cfg.get(
        "Module2_DNS",
        "stevenblack_hosts_url",
        fallback="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    )
    interval = int(cfg.get("Module2_DNS", "blocklist_update_interval_hours", fallback="24"))

    def on_block(domain: str, reason: str, lev_dist: int, client_ip: str) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        h = coc.network_event_hash(domain, client_ip, ts)
        coc.log_event(
            {
                "event_type": "DNS_BLOCK",
                "domain": domain,
                "ip_address": client_ip,
                "sha256_hash": h,
                "trigger_details": reason,
            }
        )
        log_dns_block(data_dir, domain, reason, lev_dist)
        on_dns_block(domain, reason, lev_dist)
        repeat_tracker.record(domain)

    classifier = DNSClassifier(store, threshold, redirect_ip)
    backup_hosts_if_needed()
    enable_proxy = cfg.getboolean("Module2_DNS", "enable_dns_proxy", fallback=True)
    is_privileged = is_admin_windows() or is_root_unix()
    fallback_hosts = not (enable_proxy and is_privileged and port == 53)
    start_blocklist_updater(store, urlhaus, steven, interval, stop_event, redirect_ip, fallback_hosts)

    if not enable_proxy:
        logger.info("DNS proxy disabled by configuration.")
        return None
    if not is_privileged:
        logger.error("DNS proxy requires administrator or root; running hosts fallback only.")
        append_blackbox_marker_hosts(store.snapshot(), redirect_ip)
        return None

    server = ThreadedDNServer(("0.0.0.0", port), BlackBoxUDPHandler, upstream, classifier, on_block)
    threading.Thread(target=server.serve_forever, name="dns-udp", daemon=True).start()
    logger.info("DNS server listening on UDP %s", port)
    return server


def is_admin_windows() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_root_unix() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
