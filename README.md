# AESCrypto Library
#### This library is designed to encrypt & decrypt plain text and files with AES algorithm
- Designed by: Mahmoud Khalid

## Requirements for Python 3
    pip install pycryptodome

## Usage
### Encrypt & decrypt plain text
```python
import aescrypto

key = 'Enter your key'
plainText = 'Enter your plain text'

# Create AES object
cipher = aescrypto.AESCrypto(key)
# Encrypt
encrypt = cipher.encrypt(plainText, add_key=True)
# Decrypt
decrypt = cipher.decrypt(encrypt, check_key=True)
```
### Encrypt & decrypt a file
```python
import aescrypto

key = 'Enter your key'
path = 'file_name.txt'

# Create AES object
cipher = aescrypto.AESCrypto(key)
# Encrypt
encrypt_status, encrypt_output_path = cipher.encrypt_file(path)
# Decrypt
decrypt_status, decrypt_output_path = cipher.decrypt_file(encrypt_output_path)
```
### Dump & load between storage and memory
```python
import aescrypto
import json

key = 'Enter your key'
path = 'file_name.json'
data = {}

# Create AES object
cipher = aescrypto.AESCrypto(key)
# Encrypt and dump
dump_status, dump_output_path = cipher.dump(
    data=json.dumps(data).encode(), path=path
)
# Decrypt and load
load_status, load_output_data = cipher.load(dump_output_path)
load_output_data = json.loads(load_output_data)
```

### Go to the test folder to check all examples
    python test/utility_unittesting.py
    python test/text_encryption_unittesting.py
    python test/file_encryption_unittesting.py
    python test/memory_encryption_unittesting.py
- If you haven't a virtual environment, please copy "aescrypto" folder into test folder to run