# filename: block_server.py
# ============================================================
import os
import time
import logging
import threading
from flask import Flask, render_template

logger = logging.getLogger("BlackBox.BlockServer")

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "dashboard_templates"))

# Disable logging for Flask to avoid spam
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return render_template('blocked.html')

class BlockServerModule:
    def __init__(self):
        self.port = 80
        self.thread = None
        self.running = False

    def start(self):
        logger.info(f"Starting Block Server on port {self.port}...")
        self.running = True
        self.thread = threading.Thread(target=self._run_flask, daemon=True)
        self.thread.start()

    def stop(self):
        logger.info("Stopping Block Server...")
        self.running = False

    def _run_flask(self):
        try:
            # Bind to 127.0.0.1 since the DNS proxy redirects to 127.0.0.1
            app.run(host="127.0.0.1", port=self.port, use_reloader=False, threaded=True)
        except Exception as e:
            logger.error(f"Block Server failed: {e}")
            self.running = False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mod = BlockServerModule()
    mod.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mod.stop()
