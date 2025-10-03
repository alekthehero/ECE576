import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization, hashes
import os

# Set the backend
backend = default_backend()

def main():
    msg_fname = input("Enter the message filename: ").strip()
    msg_path = os.path.join(os.path.dirname(__file__), msg_fname)
    with open(msg_path, 'rb') as f:
        data = f.read()
    myhash = hashes.SHA256()
    hasher = hashes.Hash(myhash, backend)
    hasher.update(data)
    digest = hasher.finalize()

    kr_fname = input("Enter your private key filename: ").strip()
    password = 'hello'
    kr_path = os.path.join(os.path.dirname(__file__), kr_fname)
    with open(kr_path, 'rb') as file:
        private_key = serialization.load_pem_private_key(
            data=file.read(),
            password=password.encode(),
            backend=backend
        )
    signature = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(myhash))
    )

    b64_sig = base64.b64encode(signature)
    b64_sig_str = b64_sig.decode('utf-8')

    sig_fname = msg_fname + '.sig'
    sig_path = os.path.join(os.path.dirname(__file__), sig_fname)
    with open(sig_path, 'w') as f:
        f.write('-----BEGIN SIGNATURE-----\n')
        f.write(b64_sig_str + '\n')
        f.write('-----END SIGNATURE-----\n')
    print(f"Signature saved to {sig_path}")

if __name__ == "__main__":
    main()
