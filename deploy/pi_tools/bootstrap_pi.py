import argparse
import paramiko
import time
import os

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pi-ip", required=True)
    p.add_argument("--laptop-ip", required=True)
    args = p.parse_args()

    PI_USER = os.environ.get("PI_USERNAME", "siddhesh")
    PI_PASS = os.environ.get("PI_PASSWORD", "123456789")

    print(f"Connecting to Pi at {args.pi_ip}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(args.pi_ip, username=PI_USER, password=PI_PASS, timeout=10)
    except Exception as e:
        print(f"Failed to connect to Pi: {e}")
        print("Make sure the Pi is turned ON and connected to your Mobile Hotspot.")
        import sys
        sys.exit(1)

    print("Killing old processes...")
    client.exec_command(f"echo '{PI_PASS}' | sudo -S pkill -f 'python -m logicward' || true")
    time.sleep(2)

    print("Restoring clean baseline...")
    client.exec_command("cd ~/Adani-Project-OT/logicward/plant/program && cp ThermalPlant_baseline.L5X live.L5X")
    time.sleep(1)

    print(f"Setting ingest URL to laptop IP {args.laptop_ip}...")
    client.exec_command(f"cd ~/Adani-Project-OT && echo 'export LOGICWARD_INGEST_URL=http://{args.laptop_ip}:8080/api/ingest' > deploy/pi.env")
    time.sleep(1)

    print("Starting run_pi.sh...")
    client.exec_command(
        f"cd ~/Adani-Project-OT && nohup bash -c '"
        f"SUDO_AGENT=1 bash deploy/run_pi.sh' > deploy/nohup.log 2>&1 &"
    )
    time.sleep(4)

    client.close()
    print("Pi is successfully reconfigured and started!")

if __name__ == "__main__":
    main()
