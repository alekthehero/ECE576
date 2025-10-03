import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding
from cryptography.hazmat.primitives import serialization

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

def write_skiv_pem(skiv_path, key, iv):
    with open(skiv_path, 'w') as f:
        f.write('-----BEGIN SKEY-----\n')
        f.write(base64.b64encode(key).decode() + '\n')
        f.write('-----END SKEY-----\n')
        f.write('-----BEGIN IV-----\n')
        f.write(base64.b64encode(iv).decode() + '\n')
        f.write('-----END IV-----\n')

def read_skiv_pem(skiv_path):
    key = iv = None
    with open(skiv_path, 'r') as f:
        lines = f.readlines()
    in_key = in_iv = False
    key_b64 = ''
    iv_b64 = ''
    for line in lines:
        if 'BEGIN SKEY' in line:
            in_key = True
        elif 'END SKEY' in line:
            in_key = False
        elif 'BEGIN IV' in line:
            in_iv = True
        elif 'END IV' in line:
            in_iv = False
        elif in_key:
            key_b64 += line.strip()
        elif in_iv:
            iv_b64 += line.strip()
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    return key, iv

def write_skivenc_pem(skivenc_path, enc_data):
    with open(skivenc_path, 'w') as f:
        f.write('-----BEGIN SKIVENC-----\n')
        f.write(base64.b64encode(enc_data).decode() + '\n')
        f.write('-----END SKIVENC-----\n')

def read_skivenc_pem(skivenc_path):
    with open(skivenc_path, 'r') as f:
        lines = f.readlines()
    in_enc = False
    enc_b64 = ''
    for line in lines:
        if 'BEGIN SKIVENC' in line:
            in_enc = True
        elif 'END SKIVENC' in line:
            in_enc = False
        elif in_enc:
            enc_b64 += line.strip()
    return base64.b64decode(enc_b64)

def encrypt_file(input_path, output_path, password, iv_password, recipient_public_key_path=None):
    salt = os.urandom(16)
    key, iv = get_key_iv(password, iv_password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    with open(input_path, 'rb') as infile:
        file_data = infile.read()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    with open(output_path, 'wb') as outfile:
        outfile.write(salt)
        outfile.write(encrypted_data)
    print(f'File encrypted and saved to {output_path}')
    skiv_path = output_path + '.skiv'
    write_skiv_pem(skiv_path, key, iv)
    print(f'SKIV PEM written to {skiv_path}')
    if recipient_public_key_path:
        with open(recipient_public_key_path, 'rb') as f:
            recipient_public_key = serialization.load_pem_public_key(f.read(), backend=backend)
        with open(skiv_path, 'rb') as f:
            skiv_data = f.read()
        try:
            enc_skiv = recipient_public_key.encrypt(
                skiv_data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            enc_skiv = base64.b64encode(skiv_data)
        skivenc_path = output_path + '_skiv.enc'
        write_skivenc_pem(skivenc_path, enc_skiv)
        print(f'Encrypted SKIV PEM written to {skivenc_path}')

def decrypt_file(input_path, output_path, password, iv_password, private_key_path=None):
    skivenc_path = input_path.replace('.enc', '_skiv.enc')
    skiv_path = input_path.replace('.enc', '.skiv')
    key = iv = None
    if os.path.exists(skivenc_path) and private_key_path:
        enc_skiv = read_skivenc_pem(skivenc_path)
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=backend)
        try:
            skiv_data = private_key.decrypt(
                enc_skiv,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            skiv_data = base64.b64decode(enc_skiv)
        with open(skiv_path, 'wb') as f:
            f.write(skiv_data)
        print(f'Decrypted SKIV PEM written to {skiv_path}')
        key, iv = read_skiv_pem(skiv_path)
        with open(input_path, 'rb') as infile:
            salt = infile.read(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            file_data = infile.read()
            decrypted_data = decryptor.update(file_data) + decryptor.finalize()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            with open(output_path, 'wb') as outfile:
                outfile.write(unpadded_data)
            print(f'File decrypted and saved to {output_path}')
    else:
        with open(input_path, 'rb') as infile:
            salt = infile.read(16)
            key, iv = get_key_iv(password, iv_password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            file_data = infile.read()
            decrypted_data = decryptor.update(file_data) + decryptor.finalize()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            with open(output_path, 'wb') as outfile:
                outfile.write(unpadded_data)
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
        recipient_public_key_path = input('Enter path to recipient public key (PEM), or leave blank: ')
        encrypt_file(input_path, output_path, password, iv_password, recipient_public_key_path if recipient_public_key_path else None)
    elif choice == '2':
        input_path = input('Enter path to file to decrypt: ')
        output_path = input('Enter output file name: ')
        password = input('Enter password for key derivation: ')
        iv_password = input('Enter initial string for IV derivation: ')
        private_key_path = input('Enter path to your private key (PEM), or leave blank: ')
        decrypt_file(input_path, output_path, password, iv_password, private_key_path if private_key_path else None)
    else:
        print('Invalid choice. Exiting.')

if __name__ == '__main__':
    main()
