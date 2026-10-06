import paramiko
import time

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print("Connecting to Pi to restart services...")
client.connect('10.119.190.53', username='siddhesh', password='123456789')

# 1. Kill any existing LogicWard python processes
print("Killing stuck processes...")
client.exec_command("sudo pkill -f 'python -m logicward'")
client.exec_command("sudo pkill -f 'deploy/run_pi.sh'")
time.sleep(2)

# 2. Restart the Pi services in the background using nohup
print("Starting fresh run_pi.sh in background...")
cmd = "cd ~/Adani-Project-OT && nohup bash -c 'SUDO_AGENT=1 bash deploy/run_pi.sh' > deploy/nohup.log 2>&1 &"
client.exec_command(cmd)
time.sleep(3)

# 3. Verify it started
stdin, stdout, stderr = client.exec_command("pgrep -af 'python -m logicward'")
print("\nRunning processes now:")
print(stdout.read().decode())

client.close()
print("Pi successfully restarted!")
