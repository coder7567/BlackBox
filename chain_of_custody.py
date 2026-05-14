import base64
import hashlib
import hmac
import json
import logging
import os
import platform
import shutil
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger("blackbox.chain")


def program_data_root() -> Path:
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        return Path(base) / "BlackBox"
    if system == "Darwin":
        return Path("/etc/blackbox")
    return Path("/etc/blackbox")


def logs_dir() -> Path:
    p = program_data_root() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_dir() -> Path:
    p = program_data_root() / "config"
    p.mkdir(parents=True, exist_ok=True)
    return p


def crash_log_path() -> Path:
    return logs_dir() / "crash.log"


def _derive_fernet_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key


def _derive_hmac_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + b"hmac",
        iterations=390000,
    )
    return kdf.derive(password.encode("utf-8"))


class MasterKeyManager:
    def __init__(self, wrap_password: str, create: bool = True) -> None:
        self.wrap_password = wrap_password
        self.master_path = config_dir() / "master.key"
        self.create = create
        self._fernet_log: Optional[Fernet] = None
        self._hmac_key: Optional[bytes] = None
        self._salt: bytes = b""
        self._lock = threading.Lock()

    def _load_or_create(self) -> None:
        with self._lock:
            if self._fernet_log is not None:
                return
            if not self.master_path.exists() and not self.create:
                raise FileNotFoundError(str(self.master_path))
            if self.master_path.exists():
                data = json.loads(self.master_path.read_text(encoding="utf-8"))
                salt = base64.b64decode(data["salt"])
                enc_key = base64.b64decode(data["encrypted_fernet_key"])
                wrap = Fernet(_derive_fernet_from_password(self.wrap_password, salt))
                raw_fernet = wrap.decrypt(enc_key)
                self._fernet_log = Fernet(raw_fernet)
                self._hmac_key = _derive_hmac_key(self.wrap_password, salt)
                self._salt = salt
            elif self.create:
                salt = os.urandom(16)
                raw_fernet = Fernet.generate_key()
                wrap = Fernet(_derive_fernet_from_password(self.wrap_password, salt))
                blob = wrap.encrypt(raw_fernet)
                payload = {
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "encrypted_fernet_key": base64.b64encode(blob).decode("ascii"),
                }
                self.master_path.write_text(json.dumps(payload), encoding="utf-8")
                self._fernet_log = Fernet(raw_fernet)
                self._hmac_key = _derive_hmac_key(self.wrap_password, salt)
                self._salt = salt
            else:
                raise FileNotFoundError(str(self.master_path))

    @property
    def fernet(self) -> Fernet:
        self._load_or_create()
        assert self._fernet_log is not None
        return self._fernet_log

    @property
    def hmac_key(self) -> bytes:
        self._load_or_create()
        assert self._hmac_key is not None
        return self._hmac_key


class ChainOfCustodyLogger:
    def __init__(
        self,
        encryption_enabled: bool,
        log_max_size_mb: int,
        hmac_check: bool,
        wrap_password: str,
    ) -> None:
        self.encryption_enabled = encryption_enabled
        self.log_max_size_bytes = max(1, log_max_size_mb) * 1024 * 1024
        self.hmac_check = hmac_check
        self._master = MasterKeyManager(wrap_password)
        self.log_path = logs_dir() / "chain_of_custody.jsonl"
        self.enc_log_path = logs_dir() / "chain_of_custody.jsonl.enc"
        self.hmac_path = logs_dir() / "logs_hmac.txt"
        self._write_lock = threading.Lock()

    def _rotate_if_needed(self) -> None:
        target = self.enc_log_path if self.encryption_enabled else self.log_path
        if target.exists() and target.stat().st_size >= self.log_max_size_bytes:
            if self.encryption_enabled:
                old = logs_dir() / "chain_of_custody_old.jsonl.enc"
            else:
                old = logs_dir() / "chain_of_custody_old.jsonl"
            if old.exists():
                old.unlink()
            shutil.move(str(target), str(old))

    def _append_plain_hmac(self, line: str) -> None:
        mac = hmac.new(self._master.hmac_key, line.encode("utf-8"), hashlib.sha256).hexdigest()
        with open(self.hmac_path, "a", encoding="utf-8") as hf:
            hf.write(mac + "\n")

    def log_event(self, entry: Dict[str, Any]) -> None:
        entry = dict(entry)
        entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        entry.setdefault("username", os.environ.get("USERNAME", os.environ.get("USER", "unknown")))
        entry.setdefault("hostname", socket.gethostname())
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self._write_lock:
            self._rotate_if_needed()
            if self.encryption_enabled:
                token = self._master.fernet.encrypt(line.encode("utf-8"))
                encoded = base64.b64encode(token).decode("ascii") + "\n"
                if self.hmac_check:
                    self._append_plain_hmac(line.strip())
                with open(self.enc_log_path, "a", encoding="utf-8") as lf:
                    lf.write(encoded)
            else:
                if self.hmac_check:
                    self._append_plain_hmac(line.strip())
                with open(self.log_path, "a", encoding="utf-8") as lf:
                    lf.write(line)

    def network_event_hash(self, domain: str, ip_address: str, ts: str) -> str:
        payload = f"{domain}|{ip_address}|{ts}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def file_sha256(path: Path, max_bytes: Optional[int] = None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        remaining = max_bytes
        while True:
            chunk_size = 1024 * 1024
            if remaining is not None:
                chunk_size = min(chunk_size, remaining)
                if chunk_size <= 0:
                    break
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return h.hexdigest()


def decrypt_logs_to_text(password: str, wrap_password: str, output_path: Path) -> None:
    master = MasterKeyManager(wrap_password, create=False)
    if password != wrap_password:
        raise ValueError("Invalid master password.")
    lines_out: List[str] = []
    enc_path = logs_dir() / "chain_of_custody.jsonl.enc"
    plain_path = logs_dir() / "chain_of_custody.jsonl"
    hmac_path = logs_dir() / "logs_hmac.txt"
    old_enc = logs_dir() / "chain_of_custody_old.jsonl.enc"
    sources: List[Path] = []
    if enc_path.exists():
        sources.append(enc_path)
    if old_enc.exists():
        sources.append(old_enc)
    if plain_path.exists():
        sources.append(plain_path)
    hmac_lines: List[str] = []
    if hmac_path.exists():
        hmac_lines = hmac_path.read_text(encoding="utf-8").splitlines()
    idx = 0
    for src in sources:
        if src.suffix == ".enc" or "enc" in src.name:
            for raw in src.read_text(encoding="utf-8").splitlines():
                if not raw.strip():
                    continue
                token = base64.b64decode(raw.encode("ascii"))
                plain = master.fernet.decrypt(token).decode("utf-8")
                if hmac_lines:
                    if idx >= len(hmac_lines):
                        raise RuntimeError("LOG TAMPERED: missing HMAC line")
                    expected = hmac.new(master.hmac_key, plain.encode("utf-8"), hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(expected, hmac_lines[idx]):
                        raise RuntimeError("LOG TAMPERED: HMAC mismatch")
                    idx += 1
                lines_out.append(plain)
        else:
            for plain in src.read_text(encoding="utf-8").splitlines():
                if not plain.strip():
                    continue
                if hmac_lines:
                    if idx >= len(hmac_lines):
                        raise RuntimeError("LOG TAMPERED: missing HMAC line")
                    expected = hmac.new(master.hmac_key, plain.encode("utf-8"), hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(expected, hmac_lines[idx]):
                        raise RuntimeError("LOG TAMPERED: HMAC mismatch")
                    idx += 1
                lines_out.append(plain)
    decoded = [json.loads(x) for x in lines_out]
    decoded.sort(key=lambda e: e.get("timestamp", ""))
    with open(output_path, "w", encoding="utf-8") as out:
        for obj in decoded:
            out.write(json.dumps(obj, ensure_ascii=False) + "\n")
