import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 4096
backend = default_backend()

def get_key_iv(password, iv_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode('utf-8'))
    iv_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    iv = iv_kdf.derive(iv_password.encode('utf-8'))
    return key, iv

def encrypt_file(input_path, output_path, password, iv_password):
    salt = os.urandom(16)
    key, iv = get_key_iv(password, iv_password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        outfile.write(salt)
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
            padded = padder.update(chunk)
            if padded:
                outfile.write(encryptor.update(padded))

        padded = padder.finalize()
        if padded:
            outfile.write(encryptor.update(padded))
        outfile.write(encryptor.finalize())
    print(f'File encrypted and saved to {output_path}')

def decrypt_file(input_path, output_path, password, iv_password):
    with open(input_path, 'rb') as infile:
        salt = infile.read(16)
        key, iv = get_key_iv(password, iv_password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        with open(output_path, 'wb') as outfile:
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    break
                decrypted = decryptor.update(chunk)
                if decrypted:
                    unpadded = unpadder.update(decrypted)
                    if unpadded:
                        outfile.write(unpadded)
            decrypted = decryptor.finalize()
            if decrypted:
                unpadded = unpadder.update(decrypted)
                if unpadded:
                    outfile.write(unpadded)
            unpadded = unpadder.finalize()
            if unpadded:
                outfile.write(unpadded)
    print(f'File decrypted and saved to {output_path}')

def main():
    print('Select operation:')
    print('1. Encrypt a file')
    print('2. Decrypt a file')
    choice = input('Enter 1 or 2: ').strip()
    if choice == '1':
        input_path = input('Enter path to file to encrypt: ')
        output_path = input('Enter output file name: ')
        password = input('Enter password for key derivation: ')
        iv_password = input('Enter initial string for IV derivation: ')
        encrypt_file(input_path, output_path, password, iv_password)
    elif choice == '2':
        input_path = input('Enter path to file to decrypt: ')
        output_path = input('Enter output file name: ')
        password = input('Enter password for key derivation: ')
        iv_password = input('Enter initial string for IV derivation: ')
        decrypt_file(input_path, output_path, password, iv_password)
    else:
        print('Invalid choice. Exiting.')

if __name__ == '__main__':
    main()
