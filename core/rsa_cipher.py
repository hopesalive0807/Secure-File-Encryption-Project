# core/rsa_cipher.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

KEY_DIR = "keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")

def generate_key_pair():
    os.makedirs(KEY_DIR, exist_ok=True)
    key = RSA.generate(2048)

    private_key = key.export_key()
    with open(PRIVATE_KEY_PATH, "wb") as priv_file:
        priv_file.write(private_key)

    public_key = key.publickey().export_key()
    with open(PUBLIC_KEY_PATH, "wb") as pub_file:
        pub_file.write(public_key)

    print("RSA Key pair generated successfully.")

def encrypt_key(aes_key):
    with open(PUBLIC_KEY_PATH, "rb") as pub_file:
        pub_key = RSA.import_key(pub_file.read())
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        return cipher_rsa.encrypt(aes_key)

def decrypt_key():
    with open(PRIVATE_KEY_PATH, "rb") as priv_file:
        priv_key = RSA.import_key(priv_file.read())
        cipher_rsa = PKCS1_OAEP.new(priv_key)

    enc_key_path = input("Enter path to encrypted AES key: ").strip()
    with open(enc_key_path, "rb") as f:
        enc_key = f.read()
        return cipher_rsa.decrypt(enc_key)
