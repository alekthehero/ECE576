from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import base64
import os

backend = default_backend()

def main():
    msg_fname = input("Enter the message filename to verify: ").strip()
    msg_path = os.path.join(os.path.dirname(__file__), msg_fname)
    with open(msg_path, 'rb') as f:
        data = f.read()
    hash = hashes.SHA256()
    hasher = hashes.Hash(hash, backend)
    hasher.update(data)
    digest = hasher.finalize()

    ku_fname = input("Enter the public key filename to verify: ").strip()
    ku_path = os.path.join(os.path.dirname(__file__), ku_fname)
    with open(ku_path, 'rb') as file:
        public_key = serialization.load_pem_public_key(
            data=file.read(),
            backend=backend
        )

    sig_fname = msg_fname + '.sig'
    sig_path = os.path.join(os.path.dirname(__file__), sig_fname)
    with open(sig_path, 'r') as f:
        lines = f.readlines()
    b64_sig = ''.join(line.strip() for line in lines if not line.startswith('-----'))
    sig_data = base64.b64decode(b64_sig.encode('utf-8'))

    try:
        public_key.verify(
            sig_data,
            digest,
            ec.ECDSA(utils.Prehashed(hash))
        )
    except InvalidSignature:
        print("Signature is INVALID.")
    else:
        print("Signature is VALID.")

if __name__ == "__main__":
    main()
