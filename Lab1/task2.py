import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# Step 1: Prompt user for password
password = input('Enter password for key derivation: ').encode('utf-8')

# Step 2: Generate a random salt (16 bytes for AES)
salt = os.urandom(16)
print(f'Salt (hex): {salt.hex()}')

# Step 3: Create a KDF for the password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,  # 128-bit key for AES
    salt=salt,
    iterations=100000,
    backend=backend
)
key = kdf.derive(password)
print(f'Key (hex): {key.hex()}')

# Step 4: Generate an IV (16 bytes for AES CBC)
iv_pt = b'ece576'
iv_kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend
)
iv = iv_kdf.derive(iv_pt)
print(f'IV (hex, from \'{iv_pt.decode()}\'): {iv.hex()}')

cipher = Cipher(
    algorithm=algorithms.AES(key),
    mode=modes.CBC(iv),
    backend=backend
)

encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

padder = padding.PKCS7(128).padder()

dummydata = b'12345678'

padded_dummydata = padder.update(dummydata) + padder.finalize()

print(f'\nCryptography of: {dummydata.decode()}\nRaw Data (hex): {dummydata.hex()}')
print(f'Padded Data (hex): {padded_dummydata.hex()}')

ciphertext = encryptor.update(padded_dummydata) + encryptor.finalize()

print(f'Ciphertext (hex): {ciphertext.hex()}')

plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print(f'Plaintext (hex): {plaintext.hex()}')
print(f'Plaintext: {plaintext.decode()}')