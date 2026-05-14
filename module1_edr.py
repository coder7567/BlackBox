import hashlib
import logging
import os
import platform
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from tenacity import retry, stop_after_attempt, wait_fixed
from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer

from chain_of_custody import ChainOfCustodyLogger, file_sha256, program_data_root

logger = logging.getLogger("blackbox.edr")

ELF_MAGIC = bytes.fromhex("7F454C46")
PE_MAGIC = b"MZ"
MACH_O_MAGICS = (
    bytes.fromhex("FEEDFACE"),
    bytes.fromhex("FEEDFACF"),
    bytes.fromhex("CAFEBABE"),
)


def expand_monitor_path(raw: str, user_home: Path) -> Path:
    expanded = os.path.expandvars(raw)
    expanded = expanded.replace("%USERPROFILE%", str(Path.home()))
    p = Path(expanded)
    if not p.is_absolute():
        p = user_home / p
    return p.resolve()


class InternetController:
    def __init__(
        self,
        block_duration: int,
        restore_quiet: int,
        can_firewall: bool,
        on_restored: Optional[Callable[[], None]] = None,
    ) -> None:
        self.block_duration = block_duration
        self.restore_quiet = restore_quiet
        self.can_firewall = can_firewall
        self.on_restored = on_restored
        self._lock = threading.Lock()
        self._blocked = False
        self._block_started = 0.0
        self._last_elf = 0.0
        self._restore_timer: Optional[threading.Timer] = None

    def is_blocked(self) -> bool:
        with self._lock:
            return self._blocked

    def mark_elf(self) -> None:
        with self._lock:
            self._last_elf = time.monotonic()

    def last_elf_monotonic(self) -> float:
        with self._lock:
            return self._last_elf

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(1), reraise=True)
    def _netsh_add_rule(self) -> None:
        if not self.can_firewall:
            logger.error("Firewall block skipped: administrator rights required.")
            return
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=BlackBox_Block_All",
            "dir=out",
            "action=block",
            "enable=yes",
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(1), reraise=True)
    def _netsh_delete_rule(self) -> None:
        if not self.can_firewall:
            return
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=BlackBox_Block_All",
        ]
        subprocess.run(cmd, check=False, capture_output=True, text=True)

    def _linux_block(self) -> None:
        if os.geteuid() != 0:
            logger.error("iptables block skipped: root required.")
            return
        subprocess.run(
            ["iptables", "-P", "OUTPUT", "DROP"],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            ["ip6tables", "-P", "OUTPUT", "DROP"],
            check=False,
            capture_output=True,
        )

    def _linux_unblock(self) -> None:
        if os.geteuid() != 0:
            return
        subprocess.run(
            ["iptables", "-P", "OUTPUT", "ACCEPT"],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            ["ip6tables", "-P", "OUTPUT", "ACCEPT"],
            check=False,
            capture_output=True,
        )

    def block_all_outbound(self) -> None:
        with self._lock:
            if self._blocked:
                self._last_elf = time.monotonic()
                return
            self._blocked = True
            self._block_started = time.monotonic()
            self._last_elf = time.monotonic()
        system = platform.system()
        try:
            if system == "Windows":
                self._netsh_add_rule()
            elif system == "Linux":
                self._linux_block()
            else:
                logger.warning("Internet block not implemented for this OS.")
        except Exception as exc:
            logger.exception("Failed to block internet: %s", exc)

    def restore_internet(self) -> None:
        with self._lock:
            self._blocked = False
            if self._restore_timer:
                self._restore_timer.cancel()
                self._restore_timer = None
        system = platform.system()
        try:
            if system == "Windows":
                self._netsh_delete_rule()
            elif system == "Linux":
                self._linux_unblock()
        except Exception as exc:
            logger.exception("Failed to restore internet: %s", exc)
        if self.on_restored:
            try:
                self.on_restored()
            except Exception:
                logger.exception("on_restored callback failed")

    def schedule_auto_restore(self) -> None:
        def _check() -> None:
            now = time.monotonic()
            with self._lock:
                if not self._blocked:
                    return
                if now - self._block_started < self.block_duration:
                    wait_s = self.block_duration - (now - self._block_started)
                    self._restore_timer = threading.Timer(wait_s, _check)
                    self._restore_timer.daemon = True
                    self._restore_timer.start()
                    return
                if now - self._last_elf < self.restore_quiet:
                    wait_s = self.restore_quiet - (now - self._last_elf)
                    self._restore_timer = threading.Timer(wait_s, _check)
                    self._restore_timer.daemon = True
                    self._restore_timer.start()
                    return
            self.restore_internet()

        delay = max(self.block_duration, 1)
        with self._lock:
            if self._restore_timer:
                self._restore_timer.cancel()
            self._restore_timer = threading.Timer(delay, _check)
            self._restore_timer.daemon = True
            self._restore_timer.start()


def read_header(path: Path, n: int = 512) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def classify_magic(header: bytes) -> Dict[str, bool]:
    h = header[:512]
    is_elf = len(h) >= 4 and h[:4] == ELF_MAGIC
    is_pe = len(h) >= 2 and h[:2] == PE_MAGIC
    is_macho = False
    for i in range(0, max(0, len(h) - 3)):
        chunk = h[i : i + 4]
        if chunk in MACH_O_MAGICS:
            is_macho = True
            break
    is_script = h.lstrip().startswith(b"#!")
    return {
        "elf": is_elf,
        "pe": is_pe,
        "macho": is_macho,
        "shellbang": is_script,
    }


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


class ZakTrapHandler(PatternMatchingEventHandler):
    def __init__(
        self,
        quarantine_dir: Path,
        blocked_ext: Set[str],
        max_size_bytes: int,
        manifest_path: Path,
        coc: ChainOfCustodyLogger,
        internet: InternetController,
        on_suspicious: Callable[[str, str], None],
        on_elf: Callable[[Path, str], None],
        ignore_prefixes: List[Path],
    ) -> None:
        super().__init__(patterns=["*"], ignore_directories=True, case_sensitive=False)
        self.quarantine_dir = quarantine_dir
        self.blocked_ext = {e.lower() for e in blocked_ext}
        self.max_size_bytes = max_size_bytes
        self.manifest_path = manifest_path
        self.coc = coc
        self.internet = internet
        self.on_suspicious = on_suspicious
        self.on_elf = on_elf
        self.ignore_prefixes = [p.resolve() for p in ignore_prefixes]
        self._processed_lock = threading.Lock()
        self._processed: Dict[str, float] = {}

    def _should_ignore(self, path: Path) -> bool:
        try:
            rp = path.resolve()
        except OSError:
            return True
        for pref in self.ignore_prefixes:
            try:
                rp.relative_to(pref)
                return True
            except ValueError:
                continue
        return False

    def _debounce(self, key: str) -> bool:
        now = time.monotonic()
        with self._processed_lock:
            last = self._processed.get(key, 0.0)
            if now - last < 1.5:
                return False
            self._processed[key] = now
            return True

    def _append_manifest(self, record: Dict[str, str]) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        import json

        with open(self.manifest_path, "a", encoding="utf-8") as mf:
            mf.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _quarantine_file(self, src: Path, reason: str) -> Optional[Path]:
        try:
            if not src.exists() or not src.is_file():
                return None
        except OSError:
            return None
        try:
            size = src.stat().st_size
        except OSError:
            return None
        if size > self.max_size_bytes:
            logger.warning("Skipping large file (%s bytes): %s", size, src)
            return None
        digest = file_sha256(src)
        new_name = f"{src.stem}_{digest}.quarantine"
        dest = self.quarantine_dir / new_name
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(src), str(dest))
        except Exception as exc:
            logger.exception("Quarantine move failed: %s", exc)
            return None
        self._lock_quarantine_windows(dest)
        self._append_manifest(
            {
                "original_path": str(src),
                "quarantine_path": str(dest),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sha256": digest,
                "reason": reason,
            }
        )
        self.coc.log_event(
            {
                "event_type": "FILE_QUARANTINE",
                "file_path": str(src),
                "sha256_hash": digest,
                "trigger_details": reason,
            }
        )
        self.on_suspicious("FILE_QUARANTINE", str(dest))
        return dest

    def _lock_quarantine_windows(self, path: Path) -> None:
        if platform.system() != "Windows":
            try:
                os.chmod(path, 0o400)
            except OSError:
                pass
            return
        try:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", "SYSTEM:(R)"],
                check=False,
                capture_output=True,
                text=True,
            )
            username = os.environ.get("USERNAME", "")
            if username:
                subprocess.run(
                    ["icacls", str(path), "/deny", f"{username}:(F)"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
        except Exception as exc:
            logger.warning("icacls failed: %s", exc)

    def _handle_path(self, path_str: str) -> None:
        path = Path(path_str)
        if self._should_ignore(path):
            return
        if not self._debounce(str(path)):
            return
        try:
            if not path.exists() or not path.is_file():
                return
        except OSError:
            return
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size > self.max_size_bytes:
            logger.warning("Skipping large file for scan: %s", path)
            return
        ext = path.suffix.lower()
        header = read_header(path)
        magic = classify_magic(header)
        reasons: List[str] = []
        if ext in self.blocked_ext:
            reasons.append(f"blocked_extension:{ext}")
        if magic["elf"]:
            reasons.append("ELF header at offset 0")
        if magic["pe"]:
            reasons.append("PE MZ header")
        if magic["macho"]:
            reasons.append("Mach-O header")
        if magic["shellbang"]:
            reasons.append("shell script shebang")
        if magic["elf"]:
            digest = file_sha256(path)
            self.coc.log_event(
                {
                    "event_type": "ELF_DETECTED",
                    "file_path": str(path),
                    "sha256_hash": digest,
                    "trigger_details": "ELF header at offset 0",
                }
            )
            self.internet.block_all_outbound()
            self.coc.log_event(
                {
                    "event_type": "INTERNET_CUT",
                    "file_path": str(path),
                    "sha256_hash": digest,
                    "trigger_details": "ELF triggered outbound firewall block",
                }
            )
            self.on_elf(path, digest)
            self.internet.schedule_auto_restore()
        if reasons:
            joined = "; ".join(reasons)
            self._quarantine_file(path, joined)

    def on_created(self, event):  # type: ignore[no-untyped-def]
        self._handle_path(event.src_path)

    def on_modified(self, event):  # type: ignore[no-untyped-def]
        self._handle_path(event.src_path)

    def on_moved(self, event):  # type: ignore[no-untyped-def]
        self._handle_path(event.dest_path)


def start_module1(
    cfg,
    coc: ChainOfCustodyLogger,
    internet: InternetController,
    on_suspicious: Callable[[str, str], None],
    on_elf: Callable[[Path, str], None],
    stop_event: threading.Event,
) -> Observer:
    user_home = Path(cfg.get("General", "user_home", fallback=str(Path.home())))
    raw_paths = cfg.get("Module1_EDR", "monitor_paths", fallback="")
    paths = [expand_monitor_path(p.strip(), user_home) for p in raw_paths.split(",") if p.strip()]
    if cfg.getboolean("Module1_EDR", "monitor_documents", fallback=False):
        paths.append((user_home / "Documents").resolve())
    quarantine = Path(
        cfg.get(
            "Module1_EDR",
            "quarantine_folder",
            fallback=str(program_data_root() / "Quarantine"),
        )
    )
    quarantine = quarantine.resolve()
    quarantine.mkdir(parents=True, exist_ok=True)
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["attrib", "+h", str(quarantine)],
                check=False,
                capture_output=True,
                text=True,
            )
        except Exception:
            pass
    blocked = cfg.get("Module1_EDR", "blocked_extensions", fallback="")
    blocked_set = set()
    for x in blocked.split(","):
        x = x.strip()
        if not x:
            continue
        if not x.startswith("."):
            x = "." + x
        blocked_set.add(x.lower())
    max_mb = int(cfg.get("Module1_EDR", "scan_max_file_size_mb", fallback="100"))
    manifest = program_data_root() / "quarantine_manifest.json"
    can_fw = is_admin_windows() or is_root_unix()
    internet.can_firewall = can_fw
    handler = ZakTrapHandler(
        quarantine_dir=quarantine,
        blocked_ext=blocked_set,
        max_size_bytes=max_mb * 1024 * 1024,
        manifest_path=manifest,
        coc=coc,
        internet=internet,
        on_suspicious=on_suspicious,
        on_elf=on_elf,
        ignore_prefixes=[quarantine],
    )
    observer = Observer()
    for p in paths:
        if p.exists():
            observer.schedule(handler, str(p), recursive=True)
            logger.info("Watching path: %s", p)
        else:
            logger.warning("Monitor path missing, skipping: %s", p)
    observer.daemon = True
    observer.start()
    return observer
