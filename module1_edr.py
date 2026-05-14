# filename: module1_edr.py
# ============================================================
import os
import time
import shutil
import logging
import subprocess
import platform
import configparser
import threading
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from chain_of_custody import log_event, hash_file

logger = logging.getLogger("BlackBox.Module1_EDR")

CONFIG_PATH = os.path.join(os.getcwd(), "config.ini")
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = "C:\\BLACKBOX\\config.ini"

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

class ZaktrapEventHandler(PatternMatchingEventHandler):
    def __init__(self, edr_module):
        super().__init__(ignore_directories=True)
        self.edr = edr_module
        
    def on_created(self, event):
        self.edr.inspect_file(event.src_path)

    def on_modified(self, event):
        self.edr.inspect_file(event.src_path)
        
    def on_moved(self, event):
        self.edr.inspect_file(event.dest_path)

class EDRModule:
    def __init__(self, trigger_callback=None):
        self.trigger_callback = trigger_callback
        
        # Parse Config
        paths_str = config.get('Module1_EDR', 'monitor_paths', fallback="%USERPROFILE%\\Downloads,%USERPROFILE%\\Desktop")
        self.monitor_paths = [os.path.expandvars(p.strip()) for p in paths_str.split(',')]
        
        exts_str = config.get('Module1_EDR', 'blocked_extensions', fallback=".sh,.elf,.bin,.exe,.scr,.bat,.ps1,.vbs,.jar,.apk")
        self.blocked_extensions = [e.strip().lower() for e in exts_str.split(',')]
        
        self.quarantine_folder = config.get('Module1_EDR', 'quarantine_folder', fallback="C:\\ProgramData\\BlackBox\\Quarantine")
        self.max_file_size_mb = config.getint('Module1_EDR', 'scan_max_file_size_mb', fallback=100)
        self.internet_block_duration = config.getint('Module1_EDR', 'internet_block_duration_seconds', fallback=300)
        
        self.observer = Observer()
        self.is_running = False
        self.lock = threading.Lock()
        
        self.internet_blocked = False
        self.block_timer = None
        
        # Ensure quarantine folder exists and is hidden
        os.makedirs(self.quarantine_folder, exist_ok=True)
        if platform.system() == "Windows":
            try:
                subprocess.run(["attrib", "+h", "+s", self.quarantine_folder], capture_output=True)
            except:
                pass

    def start(self):
        logger.info("Starting ZAK-TRAP File Watcher...")
        self.is_running = True
        event_handler = ZaktrapEventHandler(self)
        
        for path in self.monitor_paths:
            if os.path.exists(path):
                logger.info(f"Monitoring path: {path}")
                self.observer.schedule(event_handler, path, recursive=True)
            else:
                logger.warning(f"Configured path does not exist: {path}")
                
        self.observer.start()

    def stop(self):
        logger.info("Stopping ZAK-TRAP...")
        self.is_running = False
        self.observer.stop()
        self.observer.join()

    def _safe_read_header(self, filepath):
        try:
            # Check size first
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if size_mb > self.max_file_size_mb:
                logger.debug(f"Skipping {filepath} (Size {size_mb:.1f}MB > {self.max_file_size_mb}MB)")
                return None
                
            with open(filepath, 'rb') as f:
                return f.read(512)
        except Exception as e:
            # File might be locked by another process or AV
            logger.debug(f"Could not read header of {filepath}: {e}")
            return None

    def inspect_file(self, filepath):
        # Ignore our own quarantine folder
        if filepath.startswith(self.quarantine_folder):
            return

        # Give the filesystem a tiny moment to flush
        time.sleep(0.1)

        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()
        
        is_malicious = False
        reason = ""
        is_elf = False

        # 1. Extension Check
        if ext in self.blocked_extensions:
            is_malicious = True
            reason = f"Blocked Extension ({ext})"

        # 2. Magic Bytes Check (If not already blocked by extension, or to upgrade severity to ELF)
        header = self._safe_read_header(filepath)
        if header:
            # ELF: 7F 45 4C 46
            if header.startswith(b'\x7fELF'):
                is_malicious = True
                is_elf = True
                reason = "ELF Header Detected"
            # PE: MZ
            elif header.startswith(b'MZ'):
                if ext not in self.blocked_extensions and not is_malicious:
                    is_malicious = True
                    reason = "Hidden PE Executable Detected"
            # Mach-O
            elif header.startswith(b'\xfe\xed\xfa\xce') or header.startswith(b'\xfe\xed\xfa\xcf') or header.startswith(b'\xca\xfe\xba\xbe'):
                if not is_malicious:
                    is_malicious = True
                    reason = "Mach-O Executable Detected"
            # Script
            elif header.startswith(b'#!'):
                if not is_malicious:
                    is_malicious = True
                    reason = "Shebang Script Detected"

        if is_malicious:
            self.quarantine_file(filepath, reason, is_elf)

    def quarantine_file(self, filepath, reason, is_elf):
        logger.warning(f"MALICIOUS FILE DETECTED: {filepath} Reason: {reason}")
        
        file_hash = hash_file(filepath)
        
        # Fire callback
        if self.trigger_callback:
            event_type = "ELF_DETECTED" if is_elf else "FILE_QUARANTINE"
            self.trigger_callback(event_type, filepath)

        # Move to quarantine
        filename = os.path.basename(filepath)
        safe_name = f"{filename}_{file_hash}.quarantine"
        dest_path = os.path.join(self.quarantine_folder, safe_name)
        
        try:
            shutil.move(filepath, dest_path)
            logger.info(f"Quarantined to: {dest_path}")
            
            # Lock it down
            if platform.system() == "Windows":
                # Remove user access, grant SYSTEM full control
                subprocess.run(["icacls", dest_path, "/inheritance:r", "/grant:r", "*S-1-5-18:(F)"], capture_output=True)
            else:
                os.chmod(dest_path, 0o400) # read only for owner
                
            # Log to chain of custody
            log_event("ELF_DETECTED" if is_elf else "FILE_QUARANTINE", {
                "file_path": filepath,
                "quarantine_path": dest_path,
                "sha256_hash": file_hash,
                "trigger_details": reason
            })
            
        except Exception as e:
            logger.error(f"Failed to quarantine {filepath}: {e}")
            
        # Action if ELF
        if is_elf:
            self.block_internet()

    def block_internet(self):
        with self.lock:
            if self.internet_blocked:
                # Already blocked, just reset timer
                if self.block_timer:
                    self.block_timer.cancel()
                self.block_timer = threading.Timer(self.internet_block_duration, self.auto_restore_internet)
                self.block_timer.start()
                logger.info(f"Internet block extended for {self.internet_block_duration}s")
                return

            logger.critical("EXECUTING ZERO-TRUST INTERNET SHUTDOWN")
            self.internet_blocked = True
            
            # Log event
            log_event("INTERNET_CUT", {
                "trigger_details": "ELF Executable Detected",
                "duration_seconds": self.internet_block_duration
            })

            if platform.system() == "Windows":
                cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                       'name="BlackBox_Block_All"', 'dir=out', 'action=block']
                subprocess.run(cmd, capture_output=True)
            else:
                subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'])
                
            # Start timer for auto-restore
            self.block_timer = threading.Timer(self.internet_block_duration, self.auto_restore_internet)
            self.block_timer.start()

    def auto_restore_internet(self):
        # Called by timer
        self.restore_internet(auto=True)

    def restore_internet(self, auto=False):
        with self.lock:
            if not self.internet_blocked:
                return
                
            logger.info("Restoring internet access...")
            self.internet_blocked = False
            if self.block_timer:
                self.block_timer.cancel()
                self.block_timer = None
                
            if platform.system() == "Windows":
                cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name="BlackBox_Block_All"']
                subprocess.run(cmd, capture_output=True)
            else:
                subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
                
            log_event("INTERNET_RESTORE", {
                "trigger_details": "Auto-restore timeout reached" if auto else "Manual Override"
            })

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mod = EDRModule(trigger_callback=lambda evt, details: print(f"Triggered: {evt} on {details}"))
    mod.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mod.stop()
