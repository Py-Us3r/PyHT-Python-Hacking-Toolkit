import sys
from cryptography.fernet import Fernet
import os

temp_dir = os.path.expandvars(r"%APPDATA%")

ruta_clave = os.path.join(temp_dir, "clave.key")

if not os.path.exists(ruta_clave):
    print("⚠️ Key file does not exist.")
    sys.exit(1)

with open(ruta_clave, "rb") as clave_archivo:
    clave = clave_archivo.read()

fernet = Fernet(clave)

archivos = sys.argv[1].split(",")

for archivo in archivos:
    if os.path.exists(archivo):  
        with open(archivo, "rb") as file:
            datos_encriptados = file.read() 

        try:
            datos = fernet.decrypt(datos_encriptados)
            with open(archivo, "wb") as file:
                file.write(datos)

            print(f"✅ File ‘{file}’ has been decrypted successfully.")
        except Exception as e:
            print(f"⚠️ Error decrypting ‘{file}’: {e}")
    else:
        print(f"⚠️ File ‘{file}’ does not exist.")
