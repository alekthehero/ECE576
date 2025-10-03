from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

backend = default_backend()

def main():
    privKey = ec.generate_private_key(ec.SECP384R1(), backend)
    pubKey = privKey.public_key()

    password = 'hello'
    pem_kr = privKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    pem_ku = pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    kr_fname = '../keystore/private/alekbec_ec_kr.pem'
    ku_fname = '../keystore/public/alekbec_ec_ku.pem'
    with open(kr_fname, 'wb') as f:
        f.write(pem_kr)
    with open(ku_fname, 'wb') as f:
        f.write(pem_ku)

    print(f"Private key saved to {kr_fname}")
    print(f"Public key saved to {ku_fname}")

    with open(kr_fname, 'rb') as file:
        loaded_private_key = serialization.load_pem_private_key(
            data=file.read(),
            password=password.encode(),
            backend=backend
        )
    with open(ku_fname, 'rb') as file:
        loaded_public_key = serialization.load_pem_public_key(
            data=file.read(),
            backend=backend
        )
    print("Keys reloaded successfully.")

if __name__ == "__main__":
    main()

