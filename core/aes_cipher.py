# core/aes_cipher.py
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CHUNK_SIZE = 64 * 1024  # 64KB

def generate_aes_key():
    return get_random_bytes(32)  # AES-256

def pad(data):
    padding = 16 - len(data) % 16
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def encrypt_file(filepath, key):
    filename = os.path.basename(filepath)
    output_path = f"output/encrypted_files/encrypted_{filename}"

    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    with open(filepath, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(iv)
        while chunk := f_in.read(CHUNK_SIZE):
            chunk = pad(chunk)
            encrypted_chunk = cipher.encrypt(chunk)
            f_out.write(encrypted_chunk)

    return output_path

def decrypt_file(filepath, key):
    filename = os.path.basename(filepath).replace("encrypted_", "decrypted_")
    output_path = f"output/decrypted_files/{filename}"

    with open(filepath, 'rb') as f_in:
        iv = f_in.read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        with open(output_path, 'wb') as f_out:
            while chunk := f_in.read(CHUNK_SIZE):
                decrypted_chunk = cipher.decrypt(chunk)
                try:
                    decrypted_chunk = unpad(decrypted_chunk)
                except:
                    pass
                f_out.write(decrypted_chunk)

    return output_path
