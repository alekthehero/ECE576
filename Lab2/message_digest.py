from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

backend = default_backend()

def main():
    userInput = input("Enter a message to hash: ")
    data = bytearray(userInput, 'utf-8')

    myhash = hashes.SHA256()
    hasher = hashes.Hash(myhash, backend)
    hasher.update(data)
    digest = hasher.finalize()
    print(f"Original data: {userInput}")
    print(f"SHA256 digest: {digest.hex()}")

    hash_algorithms = [
        ("MD5", hashes.MD5()),
        ("SHA1", hashes.SHA1()),
        ("SHA256", hashes.SHA256()),
        ("SHA384", hashes.SHA384()),
        ("SHA512", hashes.SHA512()),
    ]
    print("\n--- Different Message Digests ---")
    for name, algo in hash_algorithms:
        hasher = hashes.Hash(algo, backend)
        hasher.update(data)
        digest = hasher.finalize()
        print(f"{name} digest: {digest.hex()}")

if __name__ == "__main__":
    main()
