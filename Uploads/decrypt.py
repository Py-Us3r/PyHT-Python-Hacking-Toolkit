import sys
from cryptography.fernet import Fernet
import os

temp_dir = os.path.expandvars(r"%APPDATA%")

ruta_clave = os.path.join(temp_dir, "clave.key")

if not os.path.exists(ruta_clave):
    print("Key file does not exist.")
    sys.exit(1)

with open(ruta_clave, "rb") as clave_archivo:
    clave = clave_archivo.read()

fernet = Fernet(clave)

file_path = os.path.join(temp_dir, "allfiles.txt")

if sys.argv[1] == file_path:
    with open(file_path, 'r') as f:
      archivos = f.read().strip().split(',')
else:
    archivos = sys.argv[1].strip().split(",")
