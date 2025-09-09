import time
import nmap
import os
import platform
from pystyle import *

def clear_console():
	if os.name == 'nt':
		os.system('cls')
	else:
		os.system('clear')	

def display_scan_results(nm, scan_type, target):
    
    print(Colorate.Horizontal(Colors.blue_to_cyan, f"\n{'='*60}", 1))
    print(Colorate.Horizontal(Colors.blue_to_cyan, f"{scan_type} SCAN RESULTS", 1))
    print(Colorate.Horizontal(Colors.blue_to_cyan, f"{'='*60}", 1))
    
    for host in nm.all_hosts():
        print(Colorate.Horizontal(Colors.blue_to_cyan, f"\n🎯 Target: {host}", 1))
        
        # Hostnames
        hostnames = nm[host].hostnames()
        if any(hostname['name'] for hostname in hostnames):
            print(Colorate.Horizontal(Colors.blue_to_cyan, "📛 Hostnames:", 1))
            for hostname in hostnames:
                if hostname['name']:
                    print(Colorate.Horizontal(Colors.blue_to_cyan, f"   → {hostname['name']} ({hostname['type']})", 1))
        
        print(Colorate.Horizontal(Colors.blue_to_cyan, f"📊 Status: {nm[host].state().upper()}", 1))
        
        # Statistics
        stats = nm.scanstats()
        print(Colorate.Horizontal(Colors.blue_to_cyan, f"⏱️  Scan duration: {stats['elapsed']} seconds", 1))
        
        # Open ports table
        print(Colorate.Horizontal(Colors.blue_to_cyan, "\n🚪 OPEN PORTS:", 1))
        print(Colorate.Horizontal(Colors.blue_to_cyan, "-" * 50, 1))
        print(Colorate.Horizontal(Colors.blue_to_cyan, f"{'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'PROTOCOL'}", 1))
        print(Colorate.Horizontal(Colors.blue_to_cyan, "-" * 50, 1))
        
        open_count = 0
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                port_info = nm[host][proto][port]
                if port_info['state'] == 'open':
                    open_count += 1
                    print(Colorate.Horizontal(Colors.blue_to_cyan, 
                          f"{port:<8} {port_info['state']:<10} {port_info['name']:<15} {proto.upper()}", 1))
        
        # Summary
        print(Colorate.Horizontal(Colors.blue_to_cyan, f"\n✅ Summary: {open_count} open port(s) found", 1))
        
        # Additional info for version/OS scans
        if scan_type in ["VERSION", "AGGRESSIVE"] and any('version' in nm[host][proto][port] for proto in nm[host].all_protocols() for port in nm[host][proto]):
            print(Colorate.Horizontal(Colors.blue_to_cyan, "\n🔍 SERVICE VERSIONS:", 1))
            for proto in nm[host].all_protocols():
                for port, info in nm[host][proto].items():
                    if info['state'] == 'open' and ('product' in info or 'version' in info):
                        version_str = f"{info.get('product', '')} {info.get('version', '')}".strip()
                        if version_str:
                            print(Colorate.Horizontal(Colors.blue_to_cyan, f"   → Port {port}: {version_str}", 1))
        
        if scan_type in ["OS DETECTION", "AGGRESSIVE"] and 'osmatch' in nm[host]:
            print(Colorate.Horizontal(Colors.blue_to_cyan, "\n💻 OS DETECTION:", 1))
            for os_match in nm[host]['osmatch']:
                print(Colorate.Horizontal(Colors.blue_to_cyan, f"   → {os_match['name']} ({os_match['accuracy']}% accuracy)", 1))

    print(Colorate.Horizontal(Colors.blue_to_cyan, f"\n{'='*60}", 1))
    print(Colorate.Horizontal(Colors.blue_to_cyan, "Scan completed successfully!", 1))
    print(Colorate.Horizontal(Colors.blue_to_cyan, f"{'='*60}", 1))

    redo = input(Colorate.Horizontal(Colors.blue_to_cyan, "Do you wanna scan again? [Y/n] "))

    if redo == 'Y':
    	clear_console()
    	main()
    elif redo == 'n':
    	quit()
    else:
    	print(Colorate.Horizontal(Colors.blue_to_cyan, "Invalid choice!", 1))

def run_scan(choice, ip):
	
	nm = nmap.PortScanner()
	scan_type = ""
	arguments = ""

	if choice == '1':
		scan_type = "FAST"
		arguments = "-F"

	elif choice == '2':
		scan_type = "STEALTH"
		arguments = "-sS"

	elif choice == '3':
		scan_type = "VERSION"
		arguments = "-sV"

	elif choice == '4':
		scan_type = "OS DETECTION"
		arguments = "-O"

	elif choice == '5':
		scan_type = "AGGRESSIVE"
		arguments = "-A"

	elif choice == '6':
		scan_type = "UDP"
		arguments = "-sU"

	elif choice == '7':
		scan_type = "CUSTOM"
		ports = input(Colorate.Horizontal(Colors.blue_to_cyan, 
                 "\nEnter ports to scan (ex: 80,443,22-100): ", 1))
		arguments = f'-p {ports}'

	else:
		print(Colorate.Horizontal(Colors.red, "Invalid choice!", 1))
		return

	print(Colorate.Horizontal(Colors.blue_to_cyan, f"\nStarting {scan_type} scan...", 1))
	try:
		nm.scan(ip, arguments=arguments)
		display_scan_results(nm, scan_type, ip)
	except nmap.PortScannerError as e:
		print(Colorate.Horizontal(Colors.red, f"Scan error: {e}", 1))
	except Exception as e:
		print(Colorate.Horizontal(Colors.red, f"Unexpected error: {e}", 1))  

def main():
	nmap_ascii = '''
	 ██████   █████ ██████   ██████   █████████   ███████████ 
	▒▒██████ ▒▒███ ▒▒██████ ██████   ███▒▒▒▒▒███ ▒▒███▒▒▒▒▒███
	 ▒███▒███ ▒███  ▒███▒█████▒███  ▒███    ▒███  ▒███    ▒███
	 ▒███▒▒███▒███  ▒███▒▒███ ▒███  ▒███████████  ▒██████████ 
	 ▒███ ▒▒██████  ▒███ ▒▒▒  ▒███  ▒███▒▒▒▒▒███  ▒███▒▒▒▒▒▒  
	 ▒███  ▒▒█████  ▒███      ▒███  ▒███    ▒███  ▒███        
	 █████  ▒▒█████ █████     █████ █████   █████ █████       
	▒▒▒▒▒    ▒▒▒▒▒ ▒▒▒▒▒     ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒          '''

	print(Colorate.Horizontal(Colors.blue_to_cyan, nmap_ascii, 1))

	ip = input(Colorate.Horizontal(Colors.blue_to_cyan, 
		"\nEnter the IP to scan: ", 1))

	clear_console()

	print(Colorate.Horizontal(Colors.blue_to_cyan, nmap_ascii, 1))

	choice = input(Colorate.Horizontal(Colors.blue_to_cyan, """
	[ 1 ] Fast Scan
	[ 2 ] Stealth Scan
	[ 3 ] Version Scan
	[ 4 ] OS Detection
	[ 5 ] Aggressive Scan
	[ 6 ] UDP Scan
	[ 7 ] Custom Port Scan\n
	Enter your choice: """, 1))

	run_scan(choice, ip)

main()  