import hashlib
import itertools
import string
import time
import psutil
import sys
from pathlib import Path

def load_password_file(filename):
    """Load hashed passwords from file"""
    passwords = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                username, hash_val = line.strip().split(':')
                passwords[username] = hash_val
    except FileNotFoundError:
        print(f"Error: {filename} not found")
        sys.exit(1)
    return passwords

def brute_force_attack(password_file, max_length=6, charset=None):
    """Execute brute force attack"""
    if charset is None:
        charset = string.ascii_lowercase + string.digits
    
    start_time = time.time()
    process = psutil.Process()
    
    print(f"Starting Brute Force Attack (max length: {max_length})")
    print(f"Charset: {charset[:20]}...")
    print(f"CPU Usage: {process.cpu_percent():.1f}%")
    
    target_passwords = load_password_file(password_file)
    cracked = {}
    attempts = 0
    
    for length in range(1, max_length + 1):
        print(f"Trying length {length}...")
        
        for candidate in itertools.product(charset, repeat=length):
            password = ''.join(candidate)
            attempts += 1
            
            # Hash candidate
            candidate_hash = hashlib.md5(password.encode()).hexdigest()
            
            # Check all targets
            for username, stored_hash in target_passwords.items():
                if candidate_hash == stored_hash and username not in cracked:
                    cracked[username] = password
                    print(f"✅ CRACKED: {username}:{password} (attempts: {attempts:,})")
            
            if len(cracked) == len(target_passwords):
                break
            
            # Progress indicator
            if attempts % 10000 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"Attempts: {attempts:,} | Rate: {rate:,.0f}/s | Elapsed: {elapsed:.1f}s")
        
        if len(cracked) == len(target_passwords):
            break
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print("\n" + "="*50)
    print("BRUTE FORCE ATTACK RESULTS")
    print("="*50)
    print(f"Total attempts: {attempts:,}")
    print(f"Total time: {total_time:.2f}s")
    print(f"Avg rate: {attempts/total_time:,.0f} attempts/s")
    print(f"CPU Usage: {process.cpu_percent():.1f}%")
    print(f"Passwords cracked: {len(cracked)}/{len(target_passwords)}")
    for user, pwd in cracked.items():
        print(f"  {user}: {pwd}")
    print("="*50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python brute_force_attack.py <passwords.txt> [max_length] [charset]")
        sys.exit(1)
    
    max_length = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    charset = sys.argv[3] if len(sys.argv) > 3 else None
    
    brute_force_attack(sys.argv[1], max_length, charset)