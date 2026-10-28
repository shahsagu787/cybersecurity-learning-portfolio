# Day 12: SSH Brute-Force Log Parser (auth.log)
log_file = "auth.log"
failed_count = 0

print("[*] Scanning auth.log for SSH 'Failed password' events...\n")

with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line:
            failed_count += 1
            print(f"[ALERT #{failed_count}] {line.strip()}")

print(f"\n[+] Scan Complete: Detected {failed_count} failed SSH login attempts.")