#!/bin/bash

EXE_ORIGINAL="$1"
EXE_FIRMADO="$EXE_ORIGINAL"

CERT="certificado.pfx"
CERT_PASS="JKLDFjlkdjfaoed98347512rtej"  # Change this password

if ! command -v osslsigncode &> /dev/null; then
    echo "❌ osslsigncode no está instalado. Instalándolo..."
    sudo apt update && sudo apt install osslsigncode -y
fi

if [ ! -f "$CERT" ]; then
    echo "🔹 Creando un certificado autofirmado..."
    openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout clave.pem -subj "/CN=Mi Empresa"
    openssl pkcs12 -export -out "$CERT" -inkey clave.pem -in cert.pem -passout pass:$CERT_PASS
    echo "✅ Certificado creado: $CERT"
else
    echo "✅ Certificado ya existe: $CERT"
fi

if [ -f "$EXE_ORIGINAL" ]; then
    echo "🔹 Firmando $EXE_ORIGINAL..."
    osslsigncode sign -pkcs12 "$CERT" -pass "$CERT_PASS" -n "My test program" -i "https://randomweb.com" \
    -ts http://timestamp.digicert.com -in "$EXE_ORIGINAL" -out "temp_signed.exe"

    mv "temp_signed.exe" "$EXE_ORIGINAL"

    echo "✅ Firma completada. Archivo firmado: $EXE_ORIGINAL"
else
    echo "❌ No se encontró $EXE_ORIGINAL. Asegúrate de que el archivo existe."
fi

rm cert.pem
rm certificado.pfx
rm clave.pem
