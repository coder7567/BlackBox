# filename: blackbox_daemon.py
# ============================================================
import os
import sys
import time
import signal
import logging
import argparse
import configparser
import threading
from tenacity import retry, wait_fixed, stop_after_attempt, retry_if_exception_type

# Setup basic logging before modules load
log_dir = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "BlackBox", "logs")
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, "daemon.log")),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("BlackBox.Daemon")

# Add current directory to path to ensure modules load
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from chain_of_custody import view_logs_cli
    from module1_edr import EDRModule
    from module2_dns import DNSModule
    from module3_alerts import AlertModule
    from module4_vm import VMModule
    from block_server import BlockServerModule
except ImportError as e:
    logger.error(f"Failed to import modules. Ensure all modules are in the same directory. {e}")
    # Don't exit here, allows testing partial builds

CONFIG_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.ini")

class BlackBoxDaemon:
    def __init__(self):
        self.running = False
        self.modules = []
        self.threads = []
        self.lock = threading.Lock()
        
        # Shared State
        self.state = {
            "internet_enabled": True,
            "zak_frustration_counter": 0,
            "vm_infected": False,
            "last_event_time": time.time()
        }

    def load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_PATH):
            config.read(CONFIG_PATH)
            logger.info("Loaded configuration.")
        else:
            logger.warning(f"Config not found at {CONFIG_PATH}. Using defaults.")
        return config

    def handle_security_event(self, event_type, details):
        """Callback fired by any module when an event occurs."""
        with self.lock:
            self.state["last_event_time"] = time.time()
            self.state["zak_frustration_counter"] += 1
            
            logger.warning(f"SECURITY EVENT: {event_type} - {details}")
            
            # Dispatch to AlertModule to play sound
            if hasattr(self, 'alert_module'):
                self.alert_module.trigger(event_type, details, self.state["zak_frustration_counter"])
                
            # If ELF detected, shut down internet
            if event_type == "ELF_DETECTED":
                self.disable_internet()
                if hasattr(self, 'vm_module'):
                    self.vm_module.trigger_restore("ELF_DETECTED")
                
            # If Frustration is too high, trigger VM restore
            if self.state["zak_frustration_counter"] >= 5:
                if hasattr(self, 'vm_module'):
                    self.vm_module.trigger_restore("MAX_FRUSTRATION")

    def disable_internet(self):
        with self.lock:
            if not self.state["internet_enabled"]:
                return
            logger.critical("SHUTTING DOWN INTERNET (Rule: BlackBox_Block_All)")
            self.state["internet_enabled"] = False
            
            # Module 1 will actually handle this, but daemon tracks state
            if hasattr(self, 'edr_module'):
                self.edr_module.block_internet()

    def restore_internet(self):
        with self.lock:
            if self.state["internet_enabled"]:
                return
            logger.info("Restoring internet access...")
            self.state["internet_enabled"] = True
            if hasattr(self, 'edr_module'):
                self.edr_module.restore_internet(auto=False)

    @retry(wait=wait_fixed(5), stop=stop_after_attempt(3), retry=retry_if_exception_type(Exception))
    def start_module(self, module_instance, name):
        try:
            logger.info(f"Starting module: {name}")
            module_instance.start()
        except Exception as e:
            logger.error(f"Module {name} crashed: {e}")
            raise e

    def run(self):
        logger.info("=== Starting Black Box Daemon ===")
        self.running = True
        
        config = self.load_config()
        
        # Initialize Modules
        try:
            self.alert_module = AlertModule(daemon_state=self.state)
            self.modules.append(("Alert System", self.alert_module))
            
            self.edr_module = EDRModule(trigger_callback=self.handle_security_event)
            self.modules.append(("EDR Watcher", self.edr_module))
            
            self.dns_module = DNSModule(trigger_callback=self.handle_security_event)
            self.modules.append(("DNS Sinkhole", self.dns_module))
            
            self.vm_module = VMModule(daemon_state=self.state)
            self.modules.append(("VM Monitor", self.vm_module))
            
            self.block_server_module = BlockServerModule()
            self.modules.append(("Block Server", self.block_server_module))
        except NameError as e:
            logger.error(f"Module init failed: {e}")
            
        # Start modules in threads
        for name, mod in self.modules:
            t = threading.Thread(target=self.start_module, args=(mod, name), daemon=True)
            self.threads.append(t)
            t.start()
            
        # Maintenance loop
        try:
            while self.running:
                time.sleep(10)
                # Reset counter if 2 minutes passed since last event
                with self.lock:
                    if time.time() - self.state["last_event_time"] > 120:
                        if self.state["zak_frustration_counter"] > 0:
                            logger.info("Resetting Frustration Counter (No events for 2 mins).")
                            self.state["zak_frustration_counter"] = 0
                            
                # Check module health via internal flags instead of thread life
            for name, mod in self.modules:
                # We check if the module has a 'running' attribute and if it's False
                # We skip VM Monitor if it was intentionally disabled
                if hasattr(mod, 'running') and not mod.running:
                    if name == "VM Monitor" and not self.state.get("vbox_available", True):
                        continue 
                    logger.error(f"Module {name} is not reporting as running. Attempting restart...")
            
        except KeyboardInterrupt:
            logger.info("Daemon interrupted by user.")
            self.stop()
        except Exception as e:
            logger.critical(f"Daemon crashed: {e}")
            self.stop()

    def stop(self):
        logger.info("=== Stopping Black Box Daemon ===")
        self.running = False
        for name, mod in self.modules:
            try:
                mod.stop()
            except Exception as e:
                logger.error(f"Error stopping {name}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Black Box Parental Security Suite")
    parser.add_argument("--start", action="store_true", help="Start the daemon interactively")
    parser.add_argument("--view-logs", action="store_true", help="View chain of custody logs")
    parser.add_argument("--restore-internet", action="store_true", help="Force restore internet")
    
    args = parser.parse_args()
    
    if args.view_logs:
        try:
            view_logs_cli()
        except NameError:
            print("Chain of custody module not available.")
        sys.exit(0)
        
    if args.restore_internet:
        print("Restoring internet (stub)...")
        # In actual implementation, we'd communicate with the running service (e.g. named pipe or local socket)
        # or just run the unblock command directly here.
        sys.exit(0)
        
    if args.start:
        daemon = BlackBoxDaemon()
        daemon.run()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
