import io
import json
import logging
import math
import os
import platform
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional

import numpy as np
from flask import Flask, Response, render_template, send_from_directory
from flask_socketio import SocketIO

logger = logging.getLogger("blackbox.alerts")

try:
    import pygame
except Exception:
    pygame = None

try:
    from pydub import AudioSegment
    from pydub.playback import _play_with_simpleaudio

    _HAS_PYDUB = True
except Exception:
    AudioSegment = None
    _play_with_simpleaudio = None
    _HAS_PYDUB = False

try:
    from win10toast import ToastNotifier
except Exception:
    ToastNotifier = None

try:
    from plyer import notification
except Exception:
    notification = None


class ZakFrustrationCounter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value = 0
        self._last_trigger = 0.0
        self._burst_times: List[float] = []

    def reset_if_idle(self, idle_seconds: float = 120.0) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last_trigger > idle_seconds:
                self._value = 0
                self._burst_times.clear()

    def increment_burst(self, window: float = 60.0) -> int:
        now = time.monotonic()
        with self._lock:
            self._last_trigger = now
            self._burst_times = [t for t in self._burst_times if now - t <= window]
            self._burst_times.append(now)
            if len(self._burst_times) >= 3:
                self._value += 1
            return len(self._burst_times)

    def value(self) -> int:
        with self._lock:
            return self._value

    def bump_minor(self) -> None:
        with self._lock:
            self._last_trigger = time.monotonic()
            self._value += 1


class AlertOrchestrator:
    def __init__(
        self,
        audio_path: Path,
        max_volume: int,
        repeat_interval: int,
        distortion_enabled: bool,
        desktop_notifications: bool,
        push_event: Callable[[Dict], None],
        notify_critical: Callable[[], None],
        internet_status: Callable[[], bool],
    ) -> None:
        self.audio_path = audio_path
        self.max_volume = max(1, min(100, max_volume))
        self.repeat_interval = repeat_interval
        self.distortion_enabled = distortion_enabled
        self.desktop_notifications = desktop_notifications
        self.push_event = push_event
        self.notify_critical = notify_critical
        self.internet_status = internet_status
        self._lock = threading.Lock()
        self._last_play_times: List[float] = []
        self._elf_repeat_stop = threading.Event()
        self._elf_thread: Optional[threading.Thread] = None
        self.zak = ZakFrustrationCounter()
        if pygame:
            try:
                pygame.mixer.init()
            except Exception as exc:
                logger.warning("pygame mixer init failed: %s", exc)

    def _recent_trigger_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._last_play_times = [t for t in self._last_play_times if now - t <= 10.0]
            return len(self._last_play_times)

    def _register_trigger(self) -> None:
        with self._lock:
            self._last_play_times.append(time.monotonic())

    def _effective_volume(self, base_percent: int) -> int:
        extra = min(40, self._recent_trigger_count() * 10)
        vol = min(self.max_volume, base_percent + extra)
        return vol

    def _play_wav_windows_beep(self) -> None:
        try:
            import winsound

            winsound.Beep(1000, 2000)
        except Exception:
            print("\a", flush=True)

    def _process_audio(self, raw: bytes, speed: float, distort: bool) -> Optional[bytes]:
        if not _HAS_PYDUB or AudioSegment is None:
            return None
        seg = AudioSegment.from_file(io.BytesIO(raw), format="wav")
        if speed != 1.0:
            seg = seg._spawn(seg.raw_data, overrides={"frame_rate": int(seg.frame_rate * speed)}).set_frame_rate(
                seg.frame_rate
            )
        if distort and self.distortion_enabled:
            samples = np.array(seg.get_array_of_samples()).astype(np.float32)
            if seg.channels == 2:
                samples = samples.reshape((-1, 2)).mean(axis=1)
            gain = 6.0
            clipped = np.clip(samples * gain, -32768, 32767).astype(np.int16)
            seg = AudioSegment(
                clipped.tobytes(),
                frame_rate=seg.frame_rate,
                sample_width=2,
                channels=1,
            )
        buf = io.BytesIO()
        seg.export(buf, format="wav")
        return buf.getvalue()

    def _play_once(self, percent: int) -> None:
        def _runner() -> None:
            counter_val = self.zak.value()
            speed = 1.0
            distort = False
            if counter_val >= 6:
                distort = True
            elif 3 <= counter_val <= 5:
                speed = 1.2
            if self.audio_path.exists():
                try:
                    raw = self.audio_path.read_bytes()
                    processed = self._process_audio(raw, speed, distort)
                    if processed and pygame and pygame.mixer.get_init():
                        snd = pygame.mixer.Sound(file=io.BytesIO(processed))
                        vol = max(0.0, min(1.0, percent / 100.0))
                        snd.set_volume(vol)
                        snd.play()
                    elif processed and _play_with_simpleaudio:
                        seg = AudioSegment.from_file(io.BytesIO(processed), format="wav")
                        gain_db = 10 * math.log10(max(percent, 1) / 100.0)
                        play = seg + gain_db
                        _play_with_simpleaudio(play)
                    else:
                        self._play_wav_windows_beep()
                except Exception as exc:
                    logger.warning("Audio playback failed: %s", exc)
                    self._play_wav_windows_beep()
            else:
                self._play_wav_windows_beep()

        threading.Thread(target=_runner, name="blackbox-audio", daemon=True).start()

    def _play_thread(self, percent: int, loop_elf: bool = False) -> None:
        if loop_elf:

            def _runner() -> None:
                while not self._elf_repeat_stop.is_set():
                    if self.internet_status():
                        break
                    self._play_once(percent)
                    for _ in range(self.repeat_interval):
                        if self._elf_repeat_stop.wait(1.0):
                            return
                    if self.internet_status():
                        break

            threading.Thread(target=_runner, name="blackbox-audio-elf", daemon=True).start()
            return
        self._play_once(percent)

    def play_quarantine(self) -> None:
        self.zak.reset_if_idle()
        self._register_trigger()
        self._play_thread(self._effective_volume(50), loop_elf=False)
        self._emit_dashboard("FILE_QUARANTINE", "medium")

    def play_dns_block(self) -> None:
        self.zak.increment_burst()
        self.zak.bump_minor()
        self._register_trigger()
        self._play_thread(self._effective_volume(60), loop_elf=False)
        self._emit_dashboard("DNS_BLOCK", "medium")

    def start_elf_alarm(self) -> None:
        self.zak.bump_minor()
        self._register_trigger()
        self._elf_repeat_stop.clear()
        if self._elf_thread and self._elf_thread.is_alive():
            return

        def _loop() -> None:
            self._play_thread(self._effective_volume(75), loop_elf=True)

        self._elf_thread = threading.Thread(target=_loop, name="elf-alarm", daemon=True)
        self._elf_thread.start()
        self.notify_critical()
        self._emit_dashboard("ELF_DETECTED", "critical")

    def stop_elf_alarm(self) -> None:
        self._elf_repeat_stop.set()

    def _emit_dashboard(self, kind: str, severity: str) -> None:
        self.push_event(
            {
                "type": kind,
                "severity": severity,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )

    def desktop_notify(self, title: str, message: str) -> None:
        if not self.desktop_notifications:
            return
        try:
            if platform.system() == "Windows" and ToastNotifier:
                ToastNotifier().show_toast(title, message, duration=8, threaded=True)
            elif notification:
                notification.notify(title=title, message=message, timeout=8)
        except Exception as exc:
            logger.warning("Desktop notification failed: %s", exc)


def create_dashboard_app(template_folder: Path) -> Flask:
    return Flask(__name__, template_folder=str(template_folder))


def register_routes(
    app: Flask,
    socketio: SocketIO,
    events_provider: Callable[[], Deque[Dict]],
    status_provider: Callable[[], Dict],
    assets_dir: Path,
) -> None:
    @app.route("/dashboard")
    def dashboard() -> str:
        return render_template("index.html")

    @app.route("/blocked")
    def blocked_page() -> str:
        video_path = assets_dir / "safety.mp4"
        exists = video_path.exists()
        if exists:
            body = (
                "<video autoplay loop muted playsinline>"
                "<source src='/static/safety.mp4' type='video/mp4'></video>"
                "<h1>Safety Training: Why We Don't Visit Phishing Sites</h1>"
            )
        else:
            body = "<div class='block-msg'>BLOCKED BY BLACK BOX</div>"
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Blocked</title>"
            "<style>body{font-family:Segoe UI,Arial;background:#111;color:#eee;text-align:center;padding:2rem;}"
            "video{max-width:90vw;max-height:70vh;border:3px solid #c00;}"
            ".block-msg{color:#f44;font-size:3rem;font-weight:bold;margin-top:2rem;}"
            "</style></head><body>"
            + body
            + "<p>This page was shown because the domain was blocked by Black Box parental filtering.</p>"
            + "</body></html>"
        )

    @app.route("/static/safety.mp4")
    def safety_video():
        return send_from_directory(str(assets_dir), "safety.mp4", conditional=True)

    @app.route("/events")
    def events_stream():
        def gen():
            while True:
                payload = {"events": list(events_provider()), "status": status_provider()}
                yield "data: " + json.dumps(payload) + "\n\n"
                time.sleep(1.0)

        return Response(gen(), mimetype="text/event-stream")

    @socketio.on("connect")
    def _connect():  # type: ignore[no-untyped-def]
        socketio.emit("status", status_provider())
