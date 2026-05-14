import logging
import platform
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from tenacity import retry, stop_after_attempt, wait_fixed

from chain_of_custody import ChainOfCustodyLogger

logger = logging.getLogger("blackbox.vm")


def which_or_path(name: str, configured: str) -> str:
    if configured and Path(configured).exists():
        return configured
    return name


def list_running_vbox(vbox: str) -> List[str]:
    try:
        out = subprocess.run(
            [vbox, "list", "runningvms"],
            capture_output=True,
            text=True,
            check=False,
        )
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]
    except FileNotFoundError:
        return []


def list_vmware_running(vmrun: str) -> List[str]:
    try:
        out = subprocess.run(
            [vmrun, "list"],
            capture_output=True,
            text=True,
            check=False,
        )
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]
    except FileNotFoundError:
        return []


def snapshot_list_vbox(vbox: str, vm_name: str) -> str:
    out = subprocess.run(
        [vbox, "snapshot", vm_name, "list"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout + out.stderr


class VMController:
    def __init__(self, cfg, coc: ChainOfCustodyLogger, on_disabled: Callable[[str], None], notify: Callable[[str, str], None]) -> None:
        self.cfg = cfg
        self.coc = coc
        self.on_disabled = on_disabled
        self.notify = notify
        self._lock = threading.Lock()
        self.auto_reset_disabled = False
        self.platform_name = cfg.get("Module4_VM", "platform", fallback="virtualbox")
        self.vm_name = cfg.get("Module4_VM", "vm_name", fallback="Zak-VM").strip('"')
        self.snapshot = cfg.get("Module4_VM", "clean_snapshot", fallback="Clean-Baseline").strip('"')
        self.delay = int(cfg.get("Module4_VM", "snapshot_restore_delay_seconds", fallback="30"))
        self.force_kill = cfg.getboolean("Module4_VM", "force_vm_kill", fallback=True)
        self.vbox = which_or_path("VBoxManage", cfg.get("Module4_VM", "vboxmanage_path", fallback=""))
        self.vmrun = which_or_path("vmrun", "")

    def _write_event_log_windows(self, message: str) -> None:
        if platform.system() != "Windows":
            logger.error("VM failure (non-Windows event log): %s", message)
            return
        try:
            subprocess.run(
                [
                    "eventcreate",
                    "/ID",
                    "1001",
                    "/L",
                    "APPLICATION",
                    "/T",
                    "ERROR",
                    "/SO",
                    "BlackBox",
                    "/D",
                    message[:1024],
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        except Exception:
            logger.error("VM failure (event log unavailable): %s", message)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=False)
    def _vbox_poweroff(self) -> None:
        subprocess.run(
            [self.vbox, "controlvm", self.vm_name, "poweroff"],
            check=True,
            capture_output=True,
            text=True,
        )

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=False)
    def _vbox_restore(self) -> None:
        subprocess.run(
            [self.vbox, "snapshot", self.vm_name, "restore", self.snapshot],
            check=True,
            capture_output=True,
            text=True,
        )

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=False)
    def _vbox_start(self) -> None:
        subprocess.run(
            [self.vbox, "startvm", self.vm_name, "--type", "headless"],
            check=True,
            capture_output=True,
            text=True,
        )

    def validate_configuration(self) -> bool:
        if not self.cfg.getboolean("Module4_VM", "enabled", fallback=True):
            return False
        if self.platform_name.lower() != "virtualbox":
            logger.info("VM platform %s not fully implemented; VirtualBox path used.", self.platform_name)
        try:
            listing = snapshot_list_vbox(self.vbox, self.vm_name)
        except FileNotFoundError:
            logger.warning("VBoxManage not found in PATH.")
            return False
        if self.snapshot not in listing:
            logger.error("Snapshot %s not found for VM %s", self.snapshot, self.vm_name)
            return False
        return True

    def detect_running_vm(self) -> bool:
        if self.platform_name.lower() == "virtualbox":
            running = list_running_vbox(self.vbox)
            return any(self.vm_name in line for line in running)
        running = list_vmware_running(self.vmrun)
        return any(self.vm_name in line for line in running)

    def maybe_skip(self) -> bool:
        if not self.cfg.getboolean("Module4_VM", "enabled", fallback=True):
            logger.info("VM module disabled in configuration.")
            return True
        if self.auto_reset_disabled:
            logger.info("VM auto-reset disabled after repeated failures.")
            return True
        if not self.detect_running_vm():
            logger.info("No managed VM running; snapshot module idle.")
            return True
        return False

    def restore_clean(self, reason: str, after_restore: Optional[Callable[[], None]] = None) -> bool:
        with self._lock:
            if self.auto_reset_disabled:
                return False
        if self.maybe_skip():
            return False
        ok = True
        msg = ""
        try:
            if self.force_kill:
                self._vbox_poweroff()
            self._vbox_restore()
            self._vbox_start()
        except Exception as exc:
            ok = False
            msg = str(exc)
            logger.exception("VM restore failed: %s", exc)
        if not ok:
            self._write_event_log_windows(f"BlackBox VM restore failed: {msg}")
            with self._lock:
                self.auto_reset_disabled = True
            self.on_disabled(msg)
            return False
        self.coc.log_event(
            {
                "event_type": "VM_RESTORE",
                "trigger_details": reason,
                "file_path": "",
                "sha256_hash": "",
            }
        )
        self.notify("Black Box", "VM has been reset. All unsaved work lost. Malware destroyed.")
        if after_restore:
            threading.Timer(self.delay, after_restore).start()
        return True
