import subprocess

subprocess.run(["sudo", "airmon-ng", "stop", "wlp0s20f3mon"])
subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"])