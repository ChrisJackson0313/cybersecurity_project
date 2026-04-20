import hashlib
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

def load_dictionary(filename):
    """Load wordlist for dictionary attack"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        print(f"Error: {filename} not found")
        return []

def dictionary_attack(password_file, dict_file):
    """Execute dictionary attack"""
    start_time = time.time()
    process = psutil.Process()
    
    print("Starting Dictionary Attack...")
    print(f"CPU Usage: {process.cpu_percent():.1f}%")
    
    target_passwords = load_password_file(password_file)
    dictionary = load_dictionary(dict_file)
    
    cracked = {}
    
    for word in dictionary:
        current_time = time.time()
        elapsed = current_time - start_time
        
        # Hash candidate password
        candidate_hash = hashlib.md5(word.encode()).hexdigest()
        
        # Check all targets
        for username, stored_hash in target_passwords.items():
            if candidate_hash == stored_hash and username not in cracked:
                cracked[username] = word
                print(f"✅ CRACKED: {username}:{word}")
        
        if len(cracked) == len(target_passwords):
            break
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print("\n" + "="*50)
    print("DICTIONARY ATTACK RESULTS")
    print("="*50)
    print(f"Total time: {total_time:.2f}s")
    print(f"CPU Usage: {process.cpu_percent():.1f}%")
    print(f"Passwords cracked: {len(cracked)}/{len(target_passwords)}")
    for user, pwd in cracked.items():
        print(f"  {user}: {pwd}")
    print("="*50)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python dictionary_attack.py <passwords.txt> <dictionary.txt>")
        sys.exit(1)
    dictionary_attack(sys.argv[1], sys.argv[2])