import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('10.119.190.53', username='siddhesh', password='123456789')

# Overwrite the hacked live program with the clean baseline
cmd = "cd ~/Adani-Project-OT/logicward/plant/program && cp ThermalPlant_baseline.L5X live.L5X"
client.exec_command(cmd)

# Verify the hashes match now
stdin, stdout, stderr = client.exec_command("cd ~/Adani-Project-OT/logicward/plant/program && sha256sum ThermalPlant_baseline.L5X live.L5X")
print(stdout.read().decode())
client.close()
