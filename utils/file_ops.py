# utils/file_ops.py
import os

def read_file(filepath):
    with open(filepath, "rb") as f:
        return f.read()

def write_file(filepath, data):
    with open(filepath, "wb") as f:
        f.write(data)

def ensure_dir_exists(path):
    os.makedirs(path, exist_ok=True)
