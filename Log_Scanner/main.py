import re
from collections import Counter 

# Define what counts as suspicious

SUSPICIOUS_PATTERNS2 = [
    'GET /.*admin.* HTTP\/1\..* 404 ',
    
    # 2. Flag 'admin' logins ONLY if they fail with a 401 Unauthorized
    'POST /.*admin.* HTTP\/1\..* 401 ',
    
    # 3. Traditional direct attacks (SQLi and Path Traversal)
    'UNION SELECT',
    '\.\.\/',
    
    # 4. Standard scanning tools
    'sqlmap|nikto|dirbuster'
]

SUSPICIOUS_PATTERNS = [
    r' 401 ',       # Failed logins (Unauthorized)
    r' 404 ',       # Page scanning (Not Found)
    r'\.\.\/',      # Path Traversal (Matches "../")
    r'UNION|SELECT' # SQL Injection (Matches database theft keywords)
]

def scan_log_file(file_path):
    ip_counter = Counter()
    alert_counter = Counter()
    
    # NEW: Track failed logins per IP to detect brute forcing
    failed_login_counter = Counter()
    
    print(f"Scanning file: {file_path}...\n")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # 1. Extract the IP address
                ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if not ip_match:
                    continue
                
                ip = ip_match.group(1)
                ip_counter[ip] += 1
                
                # 2. BRUTE FORCE CHECK: Look for failed logins (POST requests + 401 status)
                # This checks if the line contains a POST request to login and returned a 401 status code
                if "POST" in line and "401" in line:
                    failed_login_counter[ip] += 1
                    
                    # If a single IP fails to log in 5 times, flag it immediately!
                    if failed_login_counter[ip] == 5:
                        print(f"[CRITICAL ALERT] Brute Force Attack Detected from IP: {ip}!")
                        print(f"  -> Threshold breached at line: {line.strip()[:80]}...")
                        alert_counter["Brute Force Attack"] += 1

                # 3. Check for standalone bad patterns (ignoring lines we already flagged as brute force)
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        alert_counter[pattern] += 1
                        print(f"[ALERT] Found '{pattern}' in line: {line.strip()[:80]}...")
                        break  
                        
        print("\n--- SCAN SUMMARY ---")
        print("Top IP Addresses by Request Count:")
        for ip, count in ip_counter.most_common(3):
            print(f"  {ip}: {count} requests")
            
        print("\nTriggered Patterns & Attacks:")
        for pattern, count in alert_counter.items():
            print(f"  '{pattern}': {count} times")
            
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")

scan_log_file("malServerLog.txt") 
