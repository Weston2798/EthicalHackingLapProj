import os
import subprocess
import psutil

# Nmap port scan
def nmap_scan(target):
    print("Performing Nmap full port scan...")
    nmap_command = f"nmap -p- -sV {target}"
    nmap_proc = subprocess.Popen(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nmap_output, nmap_error = nmap_proc.communicate()
    
    if nmap_error:
        print(f"Nmap error: {nmap_error.decode()}")
    else:
        print(nmap_output.decode())

# OpenVAS vulnerability scan
def openvas_scan(target):
    print("Performing OpenVAS vulnerability scan...")
    openvas_command = f"omp -u <username> -w <password> -X '<target_ip>{target}</target_ip>' -c <config_id>"
    openvas_proc = subprocess.Popen(openvas_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    openvas_output, openvas_error = openvas_proc.communicate()
    
    if openvas_error:
        print(f"OpenVAS error: {openvas_error.decode()}")
    else:
        print(openvas_output.decode())

# Intrusion detection
def intrusion_detection():
    print("Monitoring for intrusions...")
    initial_processes = set([p.info for p in psutil.process_iter(['name', 'exe', 'username'])])
    
    while True:
        current_processes = set([p.info for p in psutil.process_iter(['name', 'exe', 'username'])])
        new_processes = current_processes - initial_processes
        
        if new_processes:
            print("Detected new processes, possible intrusion:")
            for process in new_processes:
                print(f"Process: {process}")
            break
        
        initial_processes = current_processes

# Main function
def main():
    target_ip = input("Enter the target IP address: ")
    nmap_scan(target_ip)
    openvas_scan(target_ip)
    intrusion_detection()

if __name__ == "__main__":
    main()
