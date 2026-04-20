# app.py — Flask API server for Password Security Lab
# Wraps secure_auth.py, PW_Project.py (dictionary_attack), brute_force_attack.py
# Place this file in the same directory as all the other project files.
#
# Install: pip install flask flask-cors bcrypt psutil
# Run:     python app.py

from flask import Flask, jsonify, request
from flask_cors import CORS
import hashlib
import itertools
import string
import time
import threading
import os
import sys
from pathlib import Path

# Import project modules (must be in same directory)
from secure_auth import SecureAuth

app = Flask(__name__)
CORS(app)  # Allow frontend to call from any origin

auth = SecureAuth()

# ─────────────────────────────────────────
# In-memory attack job store
# ─────────────────────────────────────────
attack_jobs = {}   # job_id -> { status, attempts, cracked, log, result }

# ─────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "message": "Password Security Lab API running"})


# ─────────────────────────────────────────
# USER MANAGEMENT (secure_auth.py)
# ─────────────────────────────────────────

@app.route('/register', methods=['POST'])
def register():
    """
    POST /register
    Body: { "username": str, "password": str }
    Returns: { "success": bool, "hash": str, "salt": str, "time_ms": float }
    """
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    start = time.time()
    password_hash, salt = auth.hash_password(password)
    elapsed_ms = round((time.time() - start) * 1000, 1)

    success = auth.create_user(username, password)
    if not success:
        # User already exists — return their hash anyway for demo purposes
        import sqlite3
        conn = sqlite3.connect(auth.db_path)
        cur = conn.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()
        return jsonify({
            "success": False,
            "error": f"User '{username}' already exists",
            "hash": row[0] if row else "",
            "salt": row[1] if row else "",
            "time_ms": elapsed_ms
        }), 409

    return jsonify({
        "success": True,
        "hash": password_hash,
        "salt": salt,
        "time_ms": elapsed_ms,
        "algorithm": "bcrypt"
    })


@app.route('/login', methods=['POST'])
def login():
    """
    POST /login
    Body: { "username": str, "password": str }
    Returns: { "success": bool, "message": str }
    """
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    # Check lockout first
    lock_time = auth.is_account_locked(username)
    if lock_time:
        from datetime import datetime
        remaining = int((lock_time - datetime.now()).total_seconds())
        return jsonify({
            "success": False,
            "locked": True,
            "message": f"Account locked. Try again in {remaining}s"
        }), 403

    result = auth.authenticate(username, password)
    return jsonify({
        "success": result,
        "message": "Authentication successful" if result else "Invalid username or password"
    })


@app.route('/users', methods=['GET'])
def list_users():
    """
    GET /users
    Returns all registered users (no passwords)
    """
    import sqlite3
    conn = sqlite3.connect(auth.db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT username, password_hash, salt, created_at, failed_attempts, locked_until FROM users")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"users": rows})


@app.route('/unlock', methods=['POST'])
def unlock():
    """
    POST /unlock
    Body: { "username": str }
    """
    data = request.get_json()
    username = data.get('username', '').strip()
    auth.unlock_account(username)
    return jsonify({"success": True, "message": f"Account '{username}' unlocked"})


# ─────────────────────────────────────────
# HASH COMPARISON
# ─────────────────────────────────────────

@app.route('/compare', methods=['POST'])
def compare():
    """
    POST /compare
    Body: { "password": str }
    Returns array of { algo, hash, time_ms, secure }
    """
    data = request.get_json()
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "Password required"}), 400

    results = []

    # bcrypt
    t = time.time()
    pw_hash, salt = auth.hash_password(password)
    results.append({"algo": "bcrypt", "hash": pw_hash, "salt": salt,
                     "time_ms": round((time.time()-t)*1000, 1), "secure": True})

    # Argon2id (if available)
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
        t = time.time()
        h = ph.hash(password)
        results.append({"algo": "argon2id", "hash": h,
                         "time_ms": round((time.time()-t)*1000, 1), "secure": True})
    except ImportError:
        results.append({"algo": "argon2id", "hash": "(pip install argon2-cffi to enable)",
                         "time_ms": None, "secure": True})

    # SHA-256 (no salt — intentionally insecure demo)
    t = time.time()
    h = hashlib.sha256(password.encode()).hexdigest()
    results.append({"algo": "sha256", "hash": h,
                     "time_ms": round((time.time()-t)*1000, 3), "secure": False})

    # MD5 (insecure — matches what generate_test_data.py uses)
    t = time.time()
    h = hashlib.md5(password.encode()).hexdigest()
    results.append({"algo": "md5", "hash": h,
                     "time_ms": round((time.time()-t)*1000, 3), "secure": False})

    return jsonify({"results": results})


# ─────────────────────────────────────────
# GENERATE TEST DATA (generate_test_data.py)
# ─────────────────────────────────────────

@app.route('/generate-test-data', methods=['POST'])
def generate_test_data():
    """
    POST /generate-test-data
    Creates test_passwords.txt with MD5 hashes (matches generate_test_data.py)
    Returns the generated entries so the frontend can display them.
    """
    weak_passwords = [
        ("admin",  "admin"),
        ("user",   "password"),
        ("test",   "123456"),
        ("guest",  "guest"),
        ("root",   "root"),
    ]

    entries = []
    with open("test_passwords.txt", "w") as f:
        for username, password in weak_passwords:
            hash_val = hashlib.md5(password.encode()).hexdigest()
            f.write(f"{username}:{hash_val}\n")
            entries.append({"username": username, "password": password,
                             "hash": hash_val, "algo": "md5"})

    return jsonify({"success": True, "entries": entries,
                    "message": "test_passwords.txt created"})


# ─────────────────────────────────────────
# DICTIONARY ATTACK (PW_Project.py logic)
# ─────────────────────────────────────────

@app.route('/attack/dictionary', methods=['POST'])
def dictionary_attack():
    """
    POST /attack/dictionary
    Body: {
      "target_hash": str,        # single MD5 hash to crack
      "wordlist": [str, ...],    # list of candidate passwords
      "username": str            # optional label
    }
    Returns: { "cracked": bool, "password": str|null, "attempts": int,
               "time_ms": float, "log": [str] }
    """
    data = request.get_json()
    target_hash = data.get('target_hash', '').strip().lower()
    wordlist     = data.get('wordlist', [])
    username     = data.get('username', 'target')

    if not target_hash or not wordlist:
        return jsonify({"error": "target_hash and wordlist required"}), 400

    start = time.time()
    log = [f"[start] Dictionary attack on {username} ({len(wordlist)} words)"]
    attempts = 0
    cracked_pw = None

    for word in wordlist:
        word = word.strip()
        if not word:
            continue
        attempts += 1
        candidate_hash = hashlib.md5(word.encode()).hexdigest()
        log.append(f"[try] '{word}' → {candidate_hash[:12]}...")

        if candidate_hash == target_hash:
            cracked_pw = word
            log.append(f"[HIT] Password cracked: '{word}' after {attempts} attempts")
            break

    elapsed_ms = round((time.time() - start) * 1000, 1)

    if not cracked_pw:
        log.append(f"[done] Wordlist exhausted. {attempts} attempts, no match.")

    return jsonify({
        "cracked": cracked_pw is not None,
        "password": cracked_pw,
        "attempts": attempts,
        "time_ms": elapsed_ms,
        "log": log
    })


# ─────────────────────────────────────────
# BRUTE FORCE ATTACK (brute_force_attack.py logic)
# ─────────────────────────────────────────

@app.route('/attack/bruteforce', methods=['POST'])
def bruteforce_attack():
    """
    POST /attack/bruteforce
    Body: {
      "target_hash": str,    # MD5 hash to crack
      "max_length": int,     # default 4
      "charset": str         # "alpha" | "alphanum" | "full"
      "username": str
    }
    Returns: { "cracked": bool, "password": str|null, "attempts": int,
               "time_ms": float, "log": [str] }

    Note: capped at max_length=6 server-side to prevent runaway requests.
    """
    data = request.get_json()
    target_hash = data.get('target_hash', '').strip().lower()
    max_length   = min(int(data.get('max_length', 4)), 6)   # hard cap at 6
    charset_key  = data.get('charset', 'alphanum')
    username     = data.get('username', 'target')

    charsets = {
        'alpha':    string.ascii_lowercase,
        'alphanum': string.ascii_lowercase + string.digits,
        'full':     string.ascii_lowercase + string.ascii_uppercase + string.digits + '!@#$%'
    }
    charset = charsets.get(charset_key, charsets['alphanum'])

    if not target_hash:
        return jsonify({"error": "target_hash required"}), 400

    start = time.time()
    log = [f"[start] Brute force on {username} (max_len={max_length}, charset={charset_key})"]
    attempts = 0
    cracked_pw = None

    for length in range(1, max_length + 1):
        log.append(f"[len={length}] Trying all {len(charset)}^{length} = {len(charset)**length:,} combinations...")
        for candidate_tuple in itertools.product(charset, repeat=length):
            password = ''.join(candidate_tuple)
            attempts += 1
            candidate_hash = hashlib.md5(password.encode()).hexdigest()

            if attempts % 5000 == 0:
                elapsed = time.time() - start
                rate = int(attempts / elapsed) if elapsed > 0 else 0
                log.append(f"[progress] {attempts:,} attempts | {rate:,}/s | current: '{password}'")

            if candidate_hash == target_hash:
                cracked_pw = password
                log.append(f"[HIT] Cracked: '{password}' after {attempts:,} attempts")
                break

        if cracked_pw:
            break

    elapsed_ms = round((time.time() - start) * 1000, 1)
    if not cracked_pw:
        log.append(f"[done] Exhausted search space. {attempts:,} attempts, no match found.")

    return jsonify({
        "cracked": cracked_pw is not None,
        "password": cracked_pw,
        "attempts": attempts,
        "time_ms": elapsed_ms,
        "log": log
    })


# ─────────────────────────────────────────
# LOGIN LOGS
# ─────────────────────────────────────────

@app.route('/logs', methods=['GET'])
def get_logs():
    """GET /logs — last 50 login attempts"""
    import sqlite3
    conn = sqlite3.connect(auth.db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM login_logs ORDER BY timestamp DESC LIMIT 50")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"logs": rows})


# ─────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 55)
    print("  Password Security Lab — Flask API")
    print("  http://localhost:5000")
    print("  Make sure secure_auth.py is in the same directory.")
    print("=" * 55)
    app.run(debug=True, port=5000)
