# Black Box Parental Security Suite - "Dad Guide"

Welcome to the **Black Box Security Suite**. This tool is designed to provide ironclad protection, active monitoring, and automatic recovery protocols to ensure a safe digital environment.

## 1. What does this do?
Black Box runs silently in the background of Windows and monitors four main things:
1. **ZAK-TRAP (File Monitoring)**: Watches the `Downloads` and `Desktop` folders. If a blocked file type (like `.exe`, `.bat`, or an invisible Linux executable) is downloaded, it instantly locks the file in a hidden Quarantine folder. If a serious threat is detected, it **cuts the internet** immediately.
2. **Linn-Mar Shield (DNS Protection)**: Blocks access to known malicious websites and catches "typosquatting" (e.g., if someone tries to go to `g00gle.com` instead of `google.com`). Blocked sites show a safety warning video.
3. **Screaming Cabbage (Alarms)**: Plays an increasingly distorted alarm sound if rules are repeatedly broken, and logs every event to a local web dashboard.
4. **Snapshot Protocol (Auto-Recovery)**: If a virus is detected or too many rules are broken, it automatically force-quits the Virtual Machine and rolls it back to a clean state.

---

## 2. Installation

1. Open **PowerShell as an Administrator** (Right-click Start -> Windows PowerShell (Admin)).
2. Navigate to this folder:
   ```powershell
   cd C:\BLACKBOX
   ```
3. Run the installer script:
   ```powershell
   .\installer.ps1
   ```
   *Note: If Windows complains about script execution policies, run `Set-ExecutionPolicy RemoteSigned` first.*

The installer will download required Python libraries and install Black Box as a Windows Service.

---

## 3. How to Run It

### Option A: Interactive Mode (Best for Testing)
To see the alerts on your screen and hear the audio properly, run the daemon manually in an Admin command prompt:
```cmd
cd C:\BLACKBOX
python blackbox_daemon.py --start
```
Leave that black window open. As long as it is open, the system is protected.

### Option B: Silent Background Service (Set-and-Forget)
If you want it to run invisibly every time the computer turns on (note: audio and desktop popups might not work in this mode due to Windows security, but the internet blocking and file quarantine will still work perfectly):
1. Open Services (`services.msc`).
2. Find **Black Box Security Daemon**.
3. Right-click and choose **Start**.

---

## 4. The Dashboard
Open a web browser and go to:
**http://localhost:8765/dashboard**

Here you can see a live feed of all security events, the "Frustration Counter", and the status of the internet uplink.

---

## 5. Reviewing the Logs (Chain of Custody)
Every time Black Box does something, it logs it securely using military-grade encryption so it cannot be tampered with.

To read the logs, open a Command Prompt and type:
```cmd
cd C:\BLACKBOX
python blackbox_daemon.py --view-logs
```
It will ask you for the Master Password.
**(Default Password: `BlackBoxSupervisor2026!`)**

It will decrypt the logs and save them to a file called `report.txt` in the same folder for you to read.

---

## 6. Fixing the Internet
If the system detects an ELF file, it will **shut down the internet** for 5 minutes.
If you need to turn the internet back on manually, run:
```cmd
python blackbox_daemon.py --restore-internet
```
Or open an Admin Command Prompt and type:
```cmd
netsh advfirewall firewall delete rule name="BlackBox_Block_All"
```
