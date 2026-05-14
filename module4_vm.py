# filename: module4_vm.py
# ============================================================
import os
import time
import subprocess
import logging
import platform
import configparser
import threading
from chain_of_custody import log_event

logger = logging.getLogger("BlackBox.Module4_VM")

CONFIG_PATH = os.path.join(os.getcwd(), "config.ini")
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = "C:\\BLACKBOX\\config.ini"

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

class VMModule:
    def __init__(self, daemon_state=None):
        self.daemon_state = daemon_state
        self.enabled = config.getboolean('Module4_VM', 'enabled', fallback=True)
        self.platform = config.get('Module4_VM', 'platform', fallback='virtualbox')
        self.vm_name = config.get('Module4_VM', 'vm_name', fallback='Zak-VM')
        self.clean_snapshot = config.get('Module4_VM', 'clean_snapshot', fallback='Clean-Baseline')
        self.safety_delay = config.getint('Module4_VM', 'snapshot_restore_delay_seconds', fallback=30)
        
        self.vm_running = False
        self.check_thread = None
        self.lock = threading.Lock()
        
        # Verify vboxmanage is in PATH
        if self.platform == 'virtualbox':
            try:
                subprocess.run(['vboxmanage', '--version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.error("vboxmanage not found in PATH or failed to execute. Disabling VM Module.")
                self.enabled = False

    def start(self):
        if not self.enabled:
            logger.info("VM Module disabled.")
            return
            
        logger.info("Starting Snapshot Protocol (VM Monitor)...")
        self.check_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.check_thread.start()

    def stop(self):
        logger.info("Stopping VM Module...")

    def _monitor_loop(self):
        while True:
            try:
                # Check if target VM is running
                if self.platform == 'virtualbox':
                    result = subprocess.run(['vboxmanage', 'list', 'runningvms'], capture_output=True, text=True)
                    self.vm_running = self.vm_name in result.stdout
                    
                    if self.daemon_state:
                        self.daemon_state["vm_infected"] = False # Reset state assumption based on running
            except Exception as e:
                logger.error(f"VM monitor error: {e}")
                
            time.sleep(10)

    def trigger_restore(self, reason):
        if not self.enabled:
            return
            
        with self.lock:
            # We restore whether it's running or not (might be paused or saved)
            logger.critical(f"TRIGGERING VM RESTORE. Reason: {reason}")
            
            if self.daemon_state:
                self.daemon_state["vm_infected"] = True
            
            success = self._execute_restore()
            
            if success:
                log_event("VM_RESTORE", {
                    "trigger_details": reason,
                    "target_vm": self.vm_name,
                    "snapshot": self.clean_snapshot
                })
                logger.info(f"Applying safety delay of {self.safety_delay}s before allowing internet restore...")
                time.sleep(self.safety_delay)
                # Internet restore is handled by the orchestrator/EDR module, 
                # but we enforce a sleep here so the orchestrator thread calling this blocks.

    def _execute_restore(self):
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                # 1. Power off (Force Kill)
                logger.info(f"Powering off VM '{self.vm_name}' (Attempt {attempt+1})...")
                subprocess.run(['vboxmanage', 'controlvm', self.vm_name, 'poweroff'], capture_output=True)
                time.sleep(2) # Give it a moment to release locks
                
                # 2. Restore Snapshot
                logger.info(f"Restoring snapshot '{self.clean_snapshot}' for VM '{self.vm_name}'...")
                res = subprocess.run(['vboxmanage', 'snapshot', self.vm_name, 'restore', self.clean_snapshot], capture_output=True, text=True)
                if res.returncode != 0:
                    logger.warning(f"Restore failed: {res.stderr}")
                    raise Exception(f"VBoxManage restore error: {res.stderr}")
                
                # 3. Start VM Headless (or GUI, but headless is safer for automated recovery)
                logger.info(f"Starting VM '{self.vm_name}'...")
                res = subprocess.run(['vboxmanage', 'startvm', self.vm_name, '--type', 'headless'], capture_output=True, text=True)
                if res.returncode != 0:
                    raise Exception(f"VBoxManage start error: {res.stderr}")
                
                logger.info("VM Restore Complete.")
                return True
                
            except Exception as e:
                logger.error(f"VM Restore attempt {attempt+1} failed: {e}")
                time.sleep(5)
                
        logger.critical("FAILED TO RESTORE VM AFTER 3 ATTEMPTS. Disabling Auto-Reset.")
        self.enabled = False
        return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mod = VMModule()
    mod.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mod.stop()
