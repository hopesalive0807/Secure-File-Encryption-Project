# core/integrity.py
import hashlib
import os

HASH_DIR = "output/hashes"
os.makedirs(HASH_DIR, exist_ok=True)

def create_hash(filepath):
    filename = os.path.basename(filepath)
    hash_path = os.path.join(HASH_DIR, f"{filename}.sha256")

    with open(filepath, "rb") as f:
        file_data = f.read()
        hash_value = hashlib.sha256(file_data).hexdigest()

    with open(hash_path, "w") as f:
        f.write(hash_value)

    return hash_value

def verify_hash(decrypted_filepath):
    filename = os.path.basename(decrypted_filepath).replace("decrypted_", "")
    hash_path = os.path.join(HASH_DIR, f"{filename}.sha256")

    if not os.path.exists(hash_path):
        print("No hash file found for verification.")
        return False

    with open(decrypted_filepath, "rb") as f:
        file_data = f.read()
        decrypted_hash = hashlib.sha256(file_data).hexdigest()

    with open(hash_path, "r") as f:
        original_hash = f.read().strip()

    if original_hash == decrypted_hash:
        print("✔ File integrity verified.")
        return True
    else:
        print("✖ File has been altered or corrupted.")
        return False
