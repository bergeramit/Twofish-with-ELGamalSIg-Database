# Twofish with ELGamalSignature Database

Databse encryption-decryption with twofish in ECB mode, secret key delivery with RSA + EL-Gamal signature.

## Twofish Implemenetation
  taken from the git repo: https://github.com/sommer/loxodo  
  tested against http://twofish.online-domain-tools.com/ - works perfectly  


## RSA Implemenetation
  Taken from the git repo: https://github.com/Amaterazu7/rsa-python  


## El Gamal Signature Implementation
  taken from: https://asecuritysite.com/encryption/el_sig

## installation 
### PowerShell steps for pycrypto 2.6.1 (via simple-crypt) / Python 3.6 / Windows 10:
```
$env:VCINSTALLDIR="C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC"
$env:CL="-FI`"$env:VCINSTALLDIR\INCLUDE\stdint.h`""
pip install pycrypto
pip install libnum
```
In order to run you need to change line 28 in "Crypto\Random\OSRNG\nt.py"  
from: 
```
import winrandom
```
to:  
```
from . import winrandom
```
