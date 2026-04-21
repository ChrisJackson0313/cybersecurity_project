Password-Cracking-Attack-Secure-Hashing-Defense-Prototype
1. Install dependencies
pip install bcrypt psutil

2. Download rockyou.txt (dictionary)
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
3. Generate test data
python generate_test_data.py

4. Run attacks (DEMO VULNERABILITIES)
python dictionary_attack.py test_passwords.txt rockyou.txt python brute_force_attack.py test_passwords.txt 4

5. Test secure system
python secure_auth.py

6. Full evaluation
python evaluation.py
