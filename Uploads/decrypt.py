import sys
from cryptography.fernet import Fernet
import os

decrypted_files = []

appdata_dir = os.path.expandvars(r"%APPDATA%")
temp_dir = os.path.expandvars(r"%tmp%")

key_path = os.path.join(temp_dir, "pass.key")

if not os.path.exists(key_path):
    print("Key file does not exist.")
    sys.exit(1)

with open(key_path, "rb") as key_file:
    decryption_key = key_file.read()

fernet = Fernet(decryption_key)

file_list_path = os.path.join(appdata_dir, "allfiles.txt")

if sys.argv[1] == file_list_path:
    with open(file_list_path, 'r') as f:
        file_list = f.read().strip().split(',')
else:
    file_list = sys.argv[1].strip().split(",")

for file_path in file_list:
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
            with open(file_path, "wb") as f:
                f.write(decrypted_data)
            decrypted_files.append(file_path)
        except Exception:
            pass
    else:
        print(f"File '{file_path}' does not exist.")

print(f"Files {decrypted_files} have been decrypted successfully.")
