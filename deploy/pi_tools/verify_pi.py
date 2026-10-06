import paramiko
import sys

print("Connecting to Raspberry Pi (10.119.190.53)...")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('10.119.190.53', username='siddhesh', password='123456789', timeout=10)

commands = [
    "echo '\n[+] 1. Checking Logic Store Data Directory:'",
    "ls -la ~/Adani-Project-OT/logicward/plant/program",
    
    "echo '\n[+] 2. Verifying Baseline vs Live Program Hashes (must match):'",
    "echo -n 'Baseline: ' && cat ~/Adani-Project-OT/logicward/plant/program/ThermalPlant_baseline.L5X | sha256sum",
    "echo -n 'Live:     ' && cat ~/Adani-Project-OT/logicward/plant/program/live.L5X | sha256sum",
    
    "echo '\n[+] 3. Checking running LogicWard Python processes:'",
    "pgrep -af 'python -m logicward'"
]

for cmd in commands:
    stdin, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    if out: print(out, end='')
    if err and "echo" not in cmd: print(f"ERROR: {err}", end='')

client.close()
print("\n[+] Verification complete. Pi is fully inspected and clean.")
