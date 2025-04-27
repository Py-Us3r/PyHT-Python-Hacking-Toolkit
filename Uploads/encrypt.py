import sys
from cryptography.fernet import Fernet
import os

temp_dir = os.path.expandvars(r"%APPDATA%")

clave = Fernet.generate_key()
ruta_clave = os.path.join(temp_dir, "clave.key")

with open(ruta_clave, "wb") as clave_archivo:
    clave_archivo.write(clave)

with open(ruta_clave, "rb") as clave_archivo:
    clave = clave_archivo.read()

fernet = Fernet(clave)

archivos = sys.argv[1].split(",")

for archivo in archivos:
    if os.path.exists(archivo):  
        with open(archivo, "rb") as file:
            datos = file.read() 

        datos_encriptados = fernet.encrypt(datos)

        with open(archivo, "wb") as file:
            file.write(datos_encriptados)

        print(f"✅ The file ‘{file}’ has been successfully encrypted.")
    else:
        print(f"⚠️ File ‘{file}’ does not exist.")


