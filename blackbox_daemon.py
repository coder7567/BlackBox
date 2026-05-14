import argparse
import configparser
import logging
import os
import signal
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional

from flask_socketio import SocketIO
from jsonschema import validate

from chain_of_custody import ChainOfCustodyLogger, crash_log_path, decrypt_logs_to_text, program_data_root
from module1_edr import InternetController, start_module1
from module2_dns import DomainRepeatTracker, run_dns_server
from module3_alerts import AlertOrchestrator, create_dashboard_app, register_routes
from module4_vm import VMController

logger = logging.getLogger("blackbox.daemon")

SCHEMA = {
    "type": "object",
    "properties": {
        "General": {"type": "object"},
        "Module1_EDR": {"type": "object"},
        "Module2_DNS": {"type": "object"},
        "Module3_Alerts": {"type": "object"},
        "Module4_VM": {"type": "object"},
        "ChainOfCustody": {"type": "object"},
    },
    "required": [
        "General",
        "Module1_EDR",
        "Module2_DNS",
        "Module3_Alerts",
        "Module4_VM",
        "ChainOfCustody",
    ],
}


def setup_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.handlers.clear()
    root.addHandler(sh)
    try:
        fh = logging.FileHandler(crash_log_path(), encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass


def excepthook(exc_type, exc, tb) -> None:
    logging.getLogger("blackbox").exception("Unhandled exception", exc_info=(exc_type, exc, tb))
    try:
        with open(crash_log_path(), "a", encoding="utf-8") as f:
            f.write(f"\nUNHANDLED: {exc_type.__name__}: {exc}\n")
    except OSError:
        pass


sys.excepthook = excepthook


def load_config() -> configparser.ConfigParser:
    base = Path(__file__).resolve().parent
    pd = program_data_root()
    pd.mkdir(parents=True, exist_ok=True)
    cfg_path = pd / "config.ini"
    if not cfg_path.exists():
        sample = base / "config.ini"
        if sample.exists():
            cfg_path.write_text(sample.read_text(encoding="utf-8"), encoding="utf-8")
    cfg = configparser.ConfigParser()
    cfg.read([str(cfg_path)], encoding="utf-8")
    blob = {s: dict(cfg.items(s)) for s in cfg.sections()}
    validate(instance=blob, schema=SCHEMA)
    return cfg


class SharedState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: Deque[Dict[str, Any]] = deque(maxlen=20)
        self.snapshot_status = "clean"
        self.vm_status = "ok"
        self.dns_hits_60s: Deque[float] = deque()
        self.critical = False

    def push_event(self, evt: Dict[str, Any]) -> None:
        with self.lock:
            self.events.appendleft(evt)
            now = time.monotonic()
            if evt.get("type") == "DNS_BLOCK":
                self.dns_hits_60s.append(now)
                while self.dns_hits_60s and now - self.dns_hits_60s[0] > 60:
                    self.dns_hits_60s.popleft()
                if len(self.dns_hits_60s) >= 3:
                    self.critical = True
            if evt.get("severity") == "critical":
                self.critical = True

    def status_dict(
        self,
        internet: InternetController,
        alerts: Optional[AlertOrchestrator],
        vm: Optional[VMController],
    ) -> Dict[str, Any]:
        with self.lock:
            events = list(self.events)
            dns60 = len(self.dns_hits_60s)
            crit = self.critical
        return {
            "events": events,
            "zak_counter": alerts.zak.value() if alerts else 0,
            "internet": "OFF" if internet.is_blocked() else "ON",
            "snapshot": self.snapshot_status,
            "dns_blocks_60s": dns60,
            "critical": crit,
            "vm_auto_reset_disabled": vm.auto_reset_disabled if vm else False,
            "vm_status": self.vm_status,
        }


def write_pid() -> None:
    pid_path = program_data_root() / "blackbox.pid"
    pid_path.write_text(str(os.getpid()), encoding="utf-8")


def read_pid() -> Optional[int]:
    pid_path = program_data_root() / "blackbox.pid"
    if not pid_path.exists():
        return None
    try:
        return int(pid_path.read_text(encoding="utf-8").strip())
    except ValueError:
        return None


def remove_pid() -> None:
    pid_path = program_data_root() / "blackbox.pid"
    if pid_path.exists():
        pid_path.unlink()


class BlackBoxDaemon:
    def __init__(self, cfg: configparser.ConfigParser) -> None:
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.shared = SharedState()
        wrap_pw = cfg.get("ChainOfCustody", "static_wrap_password", fallback="BlackBoxSupervisor2026!")
        self.coc = ChainOfCustodyLogger(
            encryption_enabled=cfg.getboolean("ChainOfCustody", "encryption_enabled", fallback=True),
            log_max_size_mb=int(cfg.get("ChainOfCustody", "log_max_size_mb", fallback="10")),
            hmac_check=cfg.getboolean("ChainOfCustody", "hmac_check", fallback=True),
            wrap_password=wrap_pw,
        )
        block_dur = int(cfg.get("Module1_EDR", "internet_block_duration_seconds", fallback="300"))
        restore_quiet = int(cfg.get("Module1_EDR", "internet_restore_quiet_seconds", fallback="60"))
        self.internet = InternetController(block_dur, restore_quiet, False, on_restored=None)
        self.repeat_tracker = DomainRepeatTracker()
        self.alerts: Optional[AlertOrchestrator] = None
        self.vm: Optional[VMController] = None
        self.socketio: Optional[SocketIO] = None
        self.dns_server = None
        self.observer = None
        self._elf_cut_active = False

    def _vm_disabled(self, message: str) -> None:
        with self.shared.lock:
            self.shared.vm_status = "disabled"
            self.shared.snapshot_status = "vm_disabled"

    def _emit_socket(self, event: str, payload: Dict[str, Any]) -> None:
        if self.socketio:
            try:
                self.socketio.emit(event, payload)
            except Exception:
                logger.exception("socket emit failed")

    def _notify_critical(self) -> None:
        self._emit_socket("critical", {"ts": time.time()})

    def _build_alerts(self) -> AlertOrchestrator:
        assets = program_data_root() / "assets"
        assets.mkdir(parents=True, exist_ok=True)
        audio = Path(self.cfg.get("Module3_Alerts", "audio_file_path", fallback=str(assets / "cabbage_scream.wav")))
        orch = AlertOrchestrator(
            audio_path=audio,
            max_volume=int(self.cfg.get("Module3_Alerts", "max_volume_percent", fallback="100")),
            repeat_interval=int(self.cfg.get("Module3_Alerts", "repeat_interval_seconds", fallback="30")),
            distortion_enabled=self.cfg.getboolean("Module3_Alerts", "distortion_enabled", fallback=True),
            desktop_notifications=self.cfg.getboolean("Module3_Alerts", "desktop_notifications", fallback=True),
            push_event=lambda e: (self.shared.push_event(e), self._emit_socket("event", e)),
            notify_critical=self._notify_critical,
            internet_status=lambda: not self.internet.is_blocked(),
        )
        return orch

    def on_suspicious(self, kind: str, detail: str) -> None:
        if self.alerts:
            if kind == "FILE_QUARANTINE":
                self.alerts.play_quarantine()
                self.alerts.desktop_notify("BLACK BOX ALERT", f"⚠️ BLACK BOX ALERT: {kind} — Check dashboard for details.")
            self.shared.snapshot_status = "infected"

    def on_elf(self, path, digest: str) -> None:
        self._elf_cut_active = True
        if self.alerts:
            self.alerts.start_elf_alarm()
            self.alerts.desktop_notify("BLACK BOX ALERT", "⚠️ BLACK BOX ALERT: ELF_DETECTED — Check dashboard for details.")
        self.shared.snapshot_status = "infected"
        if self.vm:
            self.vm.restore_clean("ELF_DETECTED", after_restore=self._delayed_enable_internet)

    def on_dns_block(self, domain: str, reason: str, lev: int) -> None:
        if self.alerts:
            self.alerts.play_dns_block()
            self.alerts.desktop_notify("BLACK BOX ALERT", f"⚠️ BLACK BOX ALERT: DNS_BLOCK — Check dashboard for details.")
        hits = self.repeat_tracker.record(domain)
        if self.vm and hits >= 3:
            self.vm.restore_clean("DNS_BLOCK_REPEATED")
        if self.alerts and self.alerts.zak.value() >= 5 and self.vm:
            self.vm.restore_clean("ZAK_FRUSTRATION")

    def _delayed_enable_internet(self) -> None:
        self.internet.restore_internet()
        if self.alerts:
            self.alerts.stop_elf_alarm()
        self._elf_cut_active = False

    def run_flask(self) -> None:
        port = int(self.cfg.get("General", "dashboard_port", fallback="8765"))
        tmpl = Path(__file__).resolve().parent / "dashboard_templates"
        app = create_dashboard_app(tmpl)
        self.socketio = SocketIO(app, async_mode="threading")
        assets = program_data_root() / "assets"
        register_routes(
            app,
            self.socketio,
            events_provider=lambda: self.shared.events,
            status_provider=lambda: self.shared.status_dict(self.internet, self.alerts, self.vm),
            assets_dir=assets,
        )
        self.socketio.run(app, host="127.0.0.1", port=port, use_reloader=False, allow_unsafe_werkzeug=True)

    def start(self) -> None:
        setup_logging(self.cfg.get("General", "log_level", fallback="INFO"))
        write_pid()
        self.alerts = self._build_alerts()
        self.internet.on_restored = lambda: self.alerts.stop_elf_alarm() if self.alerts else None
        self.vm = VMController(
            self.cfg,
            self.coc,
            on_disabled=self._vm_disabled,
            notify=lambda t, m: self.alerts.desktop_notify(t, m) if self.alerts else None,
        )
        if not self.vm.validate_configuration():
            logger.warning("VM module configuration invalid or VBox unavailable; VM restore may be skipped.")

        def edr_worker() -> None:
            self.observer = start_module1(
                self.cfg,
                self.coc,
                self.internet,
                self.on_suspicious,
                self.on_elf,
                self.stop_event,
            )
            while not self.stop_event.wait(3600):
                pass

        def dns_worker() -> None:
            self.dns_server = run_dns_server(
                self.cfg,
                self.coc,
                self.on_dns_block,
                self.repeat_tracker,
                self.stop_event,
            )
            while not self.stop_event.wait(3600):
                pass

        threading.Thread(target=edr_worker, name="edr", daemon=True).start()
        threading.Thread(target=dns_worker, name="dns", daemon=True).start()
        threading.Thread(target=self.run_flask, name="flask", daemon=False).start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        remove_pid()


BlackBoxWindowsService = None
if sys.platform == "win32":
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil

        class BlackBoxWindowsService(win32serviceutil.ServiceFramework):
            _svc_name_ = "BlackBox"
            _svc_display_name_ = "Black Box Parental Security"
            _svc_description_ = "BLACK BOX unified parental security daemon"

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
                self.daemon: Optional[BlackBoxDaemon] = None

            def SvcStop(self) -> None:
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, 0)
                if self.daemon:
                    self.daemon.stop()
                win32event.SetEvent(self.hWaitStop)

            def SvcDoRun(self) -> None:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
                self.daemon = BlackBoxDaemon(load_config())
                threading.Thread(target=self.daemon.start, name="blackbox-main", daemon=True).start()
                win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

    except ImportError:
        BlackBoxWindowsService = None


def cmd_start(cfg: configparser.ConfigParser) -> None:
    d = BlackBoxDaemon(cfg)

    def _handle_signal(_sig=None, _frame=None) -> None:
        d.stop_event.set()

    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)
    d.start()
    try:
        while not d.stop_event.wait(1):
            pass
    except KeyboardInterrupt:
        d.stop_event.set()
    finally:
        d.stop()


def cmd_stop() -> None:
    pid = read_pid()
    if not pid:
        print("Not running (no pid file).")
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception as exc:
        print(f"Failed to signal process: {exc}")


def cmd_status() -> None:
    pid = read_pid()
    print("RUNNING" if pid else "STOPPED", pid or "")


def cmd_restore_internet(cfg: configparser.ConfigParser) -> None:
    wrap_pw = cfg.get("ChainOfCustody", "static_wrap_password", fallback="BlackBoxSupervisor2026!")
    block_dur = int(cfg.get("Module1_EDR", "internet_block_duration_seconds", fallback="300"))
    restore_quiet = int(cfg.get("Module1_EDR", "internet_restore_quiet_seconds", fallback="60"))
    ic = InternetController(block_dur, restore_quiet, True, on_restored=None)
    ic.restore_internet()
    print("Internet restore command issued.")


def cmd_view_logs(cfg: configparser.ConfigParser) -> None:
    import getpass

    pw = getpass.getpass("Master password: ")
    wrap = cfg.get("ChainOfCustody", "static_wrap_password", fallback="BlackBoxSupervisor2026!")
    out = program_data_root() / "logs" / "report.txt"
    decrypt_logs_to_text(pw, wrap, out)
    print(f"Decrypted log written to {out}")


def main() -> None:
    if len(sys.argv) > 1:
        sub = sys.argv[1].lower()
        if sub in ("install", "remove", "start", "stop", "restart", "debug"):
            if BlackBoxWindowsService is None:
                print("Windows service commands require pywin32 (pip install pywin32).")
                sys.exit(1)
            import win32serviceutil

            win32serviceutil.HandleCommandLine(BlackBoxWindowsService)
            return
    parser = argparse.ArgumentParser(description="Black Box parental security daemon")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--restore-internet", action="store_true")
    parser.add_argument("--view-logs", action="store_true")
    args = parser.parse_args()
    cfg = load_config()
    if args.stop:
        cmd_stop()
    elif args.status:
        cmd_status()
    elif args.restore_internet:
        cmd_restore_internet(cfg)
    elif args.view_logs:
        cmd_view_logs(cfg)
    elif args.start:
        cmd_start(cfg)
    elif not any([args.stop, args.status, args.restore_internet, args.view_logs]):
        print("Usage: python blackbox_daemon.py --start | --stop | --status | --restore-internet | --view-logs")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
