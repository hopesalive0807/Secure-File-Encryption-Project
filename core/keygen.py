# core/keygen.py
from . import rsa_cipher

def generate_keys():
    rsa_cipher.generate_key_pair()
