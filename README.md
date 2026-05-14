# Black Box — Parental Security Suite

Black Box is a Windows-first parental security tool that watches sensitive download folders, blocks risky DNS names, plays attention-getting alerts, and can reset a dedicated study virtual machine after serious events.

## What you need

- A Windows 10 or 11 PC (other systems are only partially supported).
- Python 3.10 or newer installed from python.org, with “Add Python to PATH” turned on.
- Administrator rights when you enable the DNS proxy or automatic internet lockout, because those features change firewall rules or bind to port 53.

## Quick setup for parents

1. Copy the entire `blackbox` folder somewhere permanent, for example `C:\Tools\blackbox`.
2. Open **PowerShell as Administrator**, go to that folder, and run:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\installer.ps1
   ```

   This creates `C:\ProgramData\BlackBox\`, copies configuration and scripts, installs Python packages, and registers the optional Windows service **BlackBox** (if pywin32 is available).

3. Edit `C:\ProgramData\BlackBox\config.ini` in Notepad. At minimum, set `[General]` `user_home` to your child’s profile path if it is not already correct, and review `[Module4_VM]` if you use VirtualBox snapshots.

4. Place optional media files:

   - `C:\ProgramData\BlackBox\assets\cabbage_scream.wav` — alarm sound.
   - `C:\ProgramData\BlackBox\assets\safety.mp4` — short clip shown on blocked DNS pages.

5. Start the daemon (foreground, good for testing):

   ```powershell
   cd C:\ProgramData\BlackBox
   python blackbox_daemon.py --start
   ```

   Keep this window open while testing. For production, prefer the Windows service after `python blackbox_daemon.py install` and `sc start BlackBox`.

6. Open the dashboard in a browser: `http://localhost:8765/dashboard`

## Everyday commands

| Command | Meaning |
| --- | --- |
| `python blackbox_daemon.py --start` | Run all modules (file watcher, DNS helper, alerts, web dashboard). |
| `python blackbox_daemon.py --stop` | Ask a running instance to exit (uses the pid file). |
| `python blackbox_daemon.py --status` | Show whether Black Box thinks it is running. |
| `python blackbox_daemon.py --restore-internet` | Manually remove the emergency outbound block rule after an ELF event. |
| `python blackbox_daemon.py --view-logs` | Decrypt the chain-of-custody log after you enter the master password from `config.ini`. |

The separate viewer also works:

```powershell
python blackbox_viewer.py --decrypt --output C:\ProgramData\BlackBox\logs\report.txt
```

## Safety and privacy

- Lists of bad domains are downloaded from public blocklist feeds and cached under `C:\ProgramData\BlackBox\`. No telemetry or “phone home” beyond those list URLs is built into this code.
- Internet cut-off uses a Windows Firewall outbound block rule named `BlackBox_Block_All`. Removing the rule or using `--restore-internet` puts connectivity back.
- Virtual machine reset is powerful: unsaved work inside the VM is lost. Only enable `[Module4_VM]` if you understand that trade-off.

## Troubleshooting

- **No DNS blocking:** confirm PowerShell was elevated; port 53 must be free. Without admin rights, Black Box falls back to editing the `hosts` file marker block only.
- **No sound:** install the WAV file above, or the code falls back to Windows beeps.
- **Service will not start:** check `C:\ProgramData\BlackBox\logs\crash.log`.

## Legal notice

This software is aggressive by design (quarantine, firewall blocks, VM power-off). Only deploy it on hardware you own and where you have informed consent from all users. The authors are not responsible for misuse.
