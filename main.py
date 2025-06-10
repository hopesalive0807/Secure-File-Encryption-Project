# main.py
from core import keygen, aes_cipher, rsa_cipher, integrity
from utils import file_ops, logger
import os
from flask import Flask, request, jsonify, send_file
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# Flask Setup
app = Flask(__name__)
SECRET_KEY = "your-secure-secret-key"
serializer = URLSafeTimedSerializer(SECRET_KEY)

ENCRYPTED_FOLDER = 'output/encrypted_files'
DECRYPTED_FOLDER = 'output/decrypted_files'

@app.route('/get_download_token', methods=['POST'])
def get_download_token():
    data = request.get_json()
    filename = data.get('filename')
    folder = data.get('folder')

    if folder not in ['encrypted', 'decrypted']:
        return jsonify({"error": "Invalid folder."}), 400

    token = serializer.dumps({'filename': filename, 'folder': folder})
    return jsonify({'token': token})

@app.route('/secure_download/<token>', methods=['GET'])
def secure_download(token):
    try:
        data = serializer.loads(token, max_age=300)  # 5 minutes
        filename = data['filename']
        folder = data['folder']

        folder_map = {
            'encrypted': ENCRYPTED_FOLDER,
            'decrypted': DECRYPTED_FOLDER
        }
        file_path = os.path.join(folder_map[folder], filename)

        if not os.path.exists(file_path):
            return jsonify({"error": "File not found."}), 404

        return send_file(file_path, as_attachment=True)

    except SignatureExpired:
        return jsonify({"error": "Token expired."}), 403
    except BadSignature:
        return jsonify({"error": "Invalid token."}), 403

# CLI Interaction
def download_file_ui():
    print("\nAvailable Encrypted Files:")
    for f in os.listdir("output/encrypted_files"):
        print(f" - {f}")

    print("\nAvailable Decrypted Files:")
    for f in os.listdir("output/decrypted_files"):
        print(f" - {f}")

    filename = input("Enter filename to download (with extension): ")
    folder = input("From which folder? (encrypted/decrypted): ").strip().lower()

    if folder == "encrypted":
        src_path = f"output/encrypted_files/{filename}"
    elif folder == "decrypted":
        src_path = f"output/decrypted_files/{filename}"
    else:
        print("Invalid folder name.")
        return

    dest = input("Enter destination path to save the file: ")
    try:
        with open(src_path, 'rb') as src_file:
            with open(dest, 'wb') as dest_file:
                dest_file.write(src_file.read())
        print("File downloaded successfully.")
        logger.log_event(f"File downloaded: {filename} to {dest}")
    except Exception as e:
        print("Error while downloading file:", e)

def main():
    print("\n==== Secure File Encryptor ====")
    print("1. Generate RSA Keys")
    print("2. Encrypt File")
    print("3. Decrypt File")
    print("4. Download Encrypted/Decrypted File")
    choice = input("Choose an option (1-4): ")

    if choice == '1':
        keygen.generate_keys()

    elif choice == '2':
        filepath = input("Enter path to file to encrypt: ")
        aes_key = aes_cipher.generate_aes_key()
        encrypted_data = aes_cipher.encrypt_file(filepath, aes_key)

        enc_key_path = f"{encrypted_data}.aeskey"
        with open(enc_key_path, "wb") as f:
            f.write(rsa_cipher.encrypt_key(aes_key))

        integrity.create_hash(filepath)
        print("File encrypted and AES key secured with RSA.")
        logger.log_event("Encryption completed for: " + filepath)

    elif choice == '3':
        enc_filepath = input("Enter path to encrypted file: ")
        decrypted_key = rsa_cipher.decrypt_key()
        aes_cipher.decrypt_file(enc_filepath, decrypted_key)
        integrity.verify_hash(enc_filepath)
        print("File decrypted successfully.")
        logger.log_event("Decryption completed for: " + enc_filepath)

    elif choice == '4':
        download_file_ui()

    else:
        print("Invalid option.")

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'web':
        app.run(debug=True)
    else:
        main()
