import bcrypt
import sqlite3
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
import psutil
import hashlib
import os

class SecureAuth:
    def __init__(self, db_path="users.db"):
        self.db_path = db_path
        self.init_db()
        self.login_attempts = {}  # {user_id: {'count': int, 'last_attempt': timestamp}}
        self.locked_accounts = {}  # {user_id: unlock_time}
        self.lockout_attempts = 5
        self.lockout_duration = 300  # 5 minutes
        
    def init_db(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Generate secure bcrypt hash with salt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8'), salt.decode('utf-8')
    
    def create_user(self, username, password):
        """Create new user with secure password hashing"""
        password_hash, salt = self.hash_password(password)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            conn.commit()
            print(f"✅ User '{username}' created successfully")
            return True
        except sqlite3.IntegrityError:
            print(f"❌ User '{username}' already exists")
            return False
        finally:
            conn.close()
    
    def is_account_locked(self, username):
        """Check if account is locked"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT locked_until FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            lock_time = datetime.fromisoformat(result[0])
            if datetime.now() < lock_time:
                return lock_time
        return None
    
    def authenticate(self, username, password):
        """Secure authentication with rate limiting"""
        # Check if account is locked
        lock_time = self.is_account_locked(username)
        if lock_time:
            remaining = (lock_time - datetime.now()).total_seconds()
            print(f"❌ Account locked. Try again in {remaining:.0f} seconds")
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            self.log_attempt(username, False)
            print("❌ User not found")
            return False
        
        user_id, stored_hash, salt = user
        
        # Rate limiting check
        if user_id in self.login_attempts:
            attempts = self.login_attempts[user_id]
            time_since_last = time.time() - attempts['last_attempt']
            
            # Reset attempts if more than 1 minute since last attempt
            if time_since_last > 60:
                self.login_attempts[user_id] = {'count': 0, 'last_attempt': time.time()}
        
        # Check attempt limit
        if user_id in self.login_attempts and self.login_attempts[user_id]['count'] >= self.lockout_attempts:
            print(f"❌ Too many failed attempts. Account locked for {self.lockout_duration//60} minutes")
            self.lock_account(user_id)
            return False
        
        # Verify password
        password_bytes = password.encode('utf-8')
        if bcrypt.checkpw(password_bytes, stored_hash.encode('utf-8')):
            # Success - reset attempts
            self.login_attempts[user_id] = {'count': 0, 'last_attempt': time.time()}
            self.log_attempt(username, True)
            print(f"✅ Authentication successful for '{username}'")
            print(f"CPU Usage during auth: {psutil.Process().cpu_percent():.1f}%")
            return True
        else:
            # Failed attempt
            if user_id not in self.login_attempts:
                self.login_attempts[user_id] = {'count': 0, 'last_attempt': time.time()}
            
            self.login_attempts[user_id]['count'] += 1
            self.login_attempts[user_id]['last_attempt'] = time.time()
            self.log_attempt(username, False)
            
            attempts_used = self.login_attempts[user_id]['count']
            print(f"❌ Authentication failed for '{username}' ({attempts_used}/{self.lockout_attempts})")
            return False
    
    def lock_account(self, user_id):
        """Lock account after too many failed attempts"""
        unlock_time = datetime.now() + timedelta(seconds=self.lockout_duration)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (self.lockout_attempts, unlock_time.isoformat(), user_id)
        )
        conn.commit()
        conn.close()
        print(f"🔒 Account {user_id} locked until {unlock_time}")
    
    def log_attempt(self, username, success):
        """Log authentication attempt"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO login_logs (username, success) VALUES (?, ?)",
            (username, success)
        )
        conn.commit()
        conn.close()
    
    def unlock_account(self, username):
        """Manually unlock account"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
            (username,)
        )
        conn.commit()
        conn.close()
        print(f"🔓 Account '{username}' unlocked")

# Test script
def test_secure_system():
    auth = SecureAuth()
    
    # Create test users with different password strengths
    test_passwords = {
        "weak": "password",
        "medium": "Password123",
        "strong": "Tr0ub4dor&3xcalibur!",
        "very_strong": "K9$m1thR3@d3r$2024!@#"
    }
    
    for username, password in test_passwords.items():
        auth.create_user(username, password)
    
    print("\n" + "="*60)
    print("TESTING SECURE AUTHENTICATION")
    print("="*60)
    
    # Test successful logins
    for username, password in test_passwords.items():
        print(f"\nTesting {username}:")
        auth.authenticate(username, password)
    
    # Test failed logins and lockout
    print(f"\nTesting lockout for 'weak':")
    for i in range(6):
        auth.authenticate("weak", "wrongpassword")
    
    # Test unlock
    print("\nUnlocking 'weak' account:")
    auth.unlock_account("weak")
    auth.authenticate("weak", "password")

if __name__ == "__main__":
    test_secure_system()