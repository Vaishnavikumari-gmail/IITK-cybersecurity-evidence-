import re
from collections import defaultdict

# Professional Cyber Threat Detection Tool for IITK Registration
def analyze_logs(log_file_path):
    print("[*] Starting Security Log Analysis...")
    
    # Storage dictionaries for tracking anomalies
    failed_logins = defaultdict(int)
    directory_traversal_flags = []
    
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                # 1. Look for Directory Traversal Attack Patterns
                if "../" in line or "etc/passwd" in line:
                    directory_traversal_flags.append(line.strip())
                
                # 2. Extract IP and Look for Brute Force (HTTP 401/403 status codes)
                # Regex matches standard IP format at the beginning of a log line
                ip_match = re.match(r'^([\d\.]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if " 401 " in line or " 403 " in line:
                        failed_logins[ip] += 1
                        
        # --- GENERATING THE SECURITY REPORT ---
        print("\n" + "="*50)
        print("          INCIDENT RESPONSE SUMMARY REPORT          ")
        print("="*50)
        
        # Report Directory Traversal Anomalies
        print(f"\n[!] Directory Traversal Probes Detected: {len(directory_traversal_flags)}")
        for alert in directory_traversal_flags:
            print(f"    -> SUSPICIOUS ACTIVITY: {alert}")
            
        # Report Brute Force Anomalies (Threshold > 5 failed attempts)
        print("\n[!] Suspected Brute Force IP Addresses:")
        brute_force_found = False
        for ip, count in failed_logins.items():
            if count > 5:
                print(f"    -> THREAT: IP {ip} generated {count} failed login attempts.")
                brute_force_found = True
        if not brute_force_found:
            print("    -> No brute force thresholds breached.")
            
        print("\n" + "="*50)
        print("[*] Analysis Complete.")
        
    except FileNotFoundError:
        print(f"[X] Critical Error: Target log file '{log_file_path}' not found.")

if __name__ == "__main__":
    # Runs the analyzer against our local file
    analyze_logs("access.log")
