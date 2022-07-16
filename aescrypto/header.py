from Crypto import Random
from Crypto.Cipher import AES
import os
import io
import typing
import struct
import hashlib


class Output:
    signature = b'AESCrypto'
    fileExtension = 'aes'


keyLength = 32

ivModes = (
    AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB
)
nonceModes = (
    AES.MODE_CTR,
)

chunkSize = 1024 * 1024
if 'ANDROID_ROOT' in os.environ:
    chunkSize = 1024 * 64
