# filename: module3_alerts.py
# ============================================================
import os
import time
import logging
import threading
import configparser
import platform
import numpy as np
import io

try:
    from plyer import notification
except ImportError:
    notification = None

from flask import Flask, render_template, Response, request
import pygame
from pydub import AudioSegment
from pydub.effects import compress_dynamic_range

logger = logging.getLogger("BlackBox.Module3_Alerts")

CONFIG_PATH = os.path.join(os.getcwd(), "config.ini")
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = "C:\\BLACKBOX\\config.ini"

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

app = Flask(__name__, template_folder="dashboard_templates")
# Disable logging for Flask to avoid spam
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class SSEManager:
    def __init__(self):
        self.listeners = []
        self.lock = threading.Lock()

    def listen(self):
        q = []
        with self.lock:
            self.listeners.append(q)
        return q

    def announce(self, msg):
        with self.lock:
            for i in reversed(range(len(self.listeners))):
                try:
                    self.listeners[i].append(msg)
                except Exception:
                    del self.listeners[i]

sse_manager = SSEManager()
alert_system = None # Global reference for Flask

@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('index.html')

@app.route('/blocked')
def blocked():
    return render_template('blocked.html')

@app.route('/stream')
def stream():
    def event_stream():
        q = sse_manager.listen()
        while True:
            if len(q) > 0:
                msg = q.pop(0)
                yield f"data: {msg}\n\n"
            time.sleep(0.1)
    return Response(event_stream(), mimetype="text/event-stream")


class AlertModule:
    def __init__(self, daemon_state=None):
        self.daemon_state = daemon_state or {"zak_frustration_counter": 0, "internet_enabled": True}
        self.enabled = True
        self.audio_file = config.get('Module3_Alerts', 'audio_file_path', fallback="C:\\ProgramData\\BlackBox\\assets\\cabbage_scream.wav")
        self.port = config.getint('General', 'dashboard_port', fallback=8765)
        
        self.audio_thread = None
        self.is_playing = False
        self.play_lock = threading.Lock()
        
        pygame.mixer.init()
        
        # Pre-load audio if it exists, otherwise we'll fall back to beeps
        self.has_audio = os.path.exists(self.audio_file)
        if not self.has_audio:
            logger.warning(f"Audio file not found: {self.audio_file}. Using system beep fallback.")

    def start(self):
        logger.info("Starting Screaming Cabbage Alert System...")
        global alert_system
        alert_system = self
        
        # Start Flask dashboard
        self.flask_thread = threading.Thread(target=self._run_flask, daemon=True)
        self.flask_thread.start()

    def stop(self):
        logger.info("Stopping Alerts...")
        # Flask is daemonized, it will die with the process.

    def _run_flask(self):
        try:
            app.run(host="0.0.0.0", port=self.port, use_reloader=False, threaded=True)
        except Exception as e:
            logger.error(f"Flask dashboard failed: {e}")

    def trigger(self, event_type, details, counter):
        # Determine volume and playback logic based on event and counter
        volume = 0.5
        repeat = False
        
        if event_type == "FILE_QUARANTINE":
            volume = 0.5
        elif event_type == "DNS_BLOCK":
            volume = 0.6
        elif event_type == "ELF_DETECTED":
            volume = 0.75
            repeat = True
            
        # Scaling based on frustration
        if counter > 1:
            volume += (counter * 0.1)
        volume = min(1.0, volume)
        
        # Trigger UI update
        import json
        event_data = {
            "type": event_type,
            "details": details,
            "counter": counter,
            "internet": self.daemon_state.get("internet_enabled", True)
        }
        sse_manager.announce(json.dumps(event_data))

        # Desktop Notification
        if config.getboolean('Module3_Alerts', 'desktop_notifications', fallback=True):
            self._send_notification(event_type, details)

        # Audio Playback
        if not self.is_playing:
            threading.Thread(target=self._play_audio, args=(volume, counter, repeat), daemon=True).start()

    def _send_notification(self, event_type, details):
        if notification:
            try:
                notification.notify(
                    title=f"⚠️ BLACK BOX ALERT: {event_type}",
                    message="Check dashboard for details.",
                    app_name="BlackBox Security"
                )
            except Exception as e:
                logger.debug(f"Notification failed (expected if Session 0): {e}")

    def _apply_distortion(self, sound_segment, counter):
        # Uses numpy and pydub to overdrive/distort the audio
        samples = np.array(sound_segment.get_array_of_samples())
        # Overdrive: multiply amplitude and clip
        gain = 1.0 + (counter * 0.5)
        samples = samples * gain
        
        # Hard clipping
        max_val = (2**(sound_segment.sample_width * 8 - 1)) - 1
        np.clip(samples, -max_val, max_val, out=samples)
        
        return sound_segment._spawn(samples.astype(np.int16).tobytes())

    def _play_audio(self, volume, counter, repeat):
        with self.play_lock:
            self.is_playing = True
            
            try:
                if not self.has_audio:
                    self._fallback_beep()
                    time.sleep(1)
                    return

                # Load with pydub for effects
                sound = AudioSegment.from_wav(self.audio_file)
                
                # Speed up if counter 3-5
                if 3 <= counter <= 5:
                    sound = sound.speedup(playback_speed=1.2)
                    
                # Distort if counter 6+
                if counter >= 6:
                    sound = self._apply_distortion(sound, counter)

                # Export to memory and load into pygame
                f = io.BytesIO()
                sound.export(f, format="wav")
                f.seek(0)
                
                pg_sound = pygame.mixer.Sound(f)
                pg_sound.set_volume(volume)
                
                if repeat:
                    pg_sound.play(loops=-1) # infinite loop
                else:
                    pg_sound.play()
                    
                # Wait for playback to finish if not repeating
                if not repeat:
                    while pygame.mixer.get_busy():
                        time.sleep(0.1)

            except Exception as e:
                logger.error(f"Audio playback error: {e}")
                self._fallback_beep()
            finally:
                if not repeat:
                    self.is_playing = False

    def _fallback_beep(self):
        if platform.system() == "Windows":
            import winsound
            winsound.Beep(1000, 2000)
        else:
            print('\a') # Terminal bell

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mod = AlertModule()
    mod.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mod.stop()
