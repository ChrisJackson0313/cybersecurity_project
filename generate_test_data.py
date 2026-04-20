import hashlib
from secure_auth import SecureAuth

def generate_test_passwords():
    """Generate test password file for cracking demos"""
    weak_passwords = [
        ("admin", "admin"),
        ("user", "password"),
        ("test", "123456"),
        ("guest", "guest"),
        ("root", "root")
    ]
    
    # Generate MD5 hashes for cracking demo
    with open("test_passwords.txt", "w") as f:
        for username, password in weak_passwords:
            hash_val = hashlib.md5(password.encode()).hexdigest()
            f.write(f"{username}:{hash_val}\n")
    
    print("✅ test_passwords.txt created")
    print("✅ Use with dictionary_attack.py or brute_force_attack.py")

def main():
    generate_test_passwords()
    
    # Also create secure users
    auth = SecureAuth()
    auth.create_user("secure_user", "Tr0ub4dor&3xcalibur!")
    print("✅ Secure test user created")

if __name__ == "__main__":
    main()