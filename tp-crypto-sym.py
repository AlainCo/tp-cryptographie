from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Constantes
FILE_NAME = "input.txt"
ENCRYPTED_FILE_NAME = "encrypted.bin"
DECRYPTED_FILE_NAME = "decrypted.txt"
KEY = b'Sixteen byte key'  # Clé de 16 octets pour AES-128 ou 32 octets pour AES-256
IV = os.urandom(16)  # Initialization Vector de 16 octets pour AES
MODE = modes.CBC(IV)  # Mode de chiffrement (ECB, CBC, GCM)

def calculate_sha256(file_name):
    with open(file_name, 'rb') as f:
        data = f.read()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize().hex()

def encrypt_file(input_file, output_file, key, mode):
    with open(input_file, 'rb') as f:
        data = f.read()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        with open(output_file, 'wb') as out_f:
            out_f.write(encrypted_data)

def decrypt_file(input_file, output_file, key, mode):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        with open(output_file, 'wb') as out_f:
            out_f.write(data)

def main():
    # Calculer et afficher le SHA-256 du fichier d'entrée
    sha256_hash = calculate_sha256(FILE_NAME)
    print(f"SHA-256 du fichier {FILE_NAME}: {sha256_hash}")

    # Chiffrer le fichier
    encrypt_file(FILE_NAME, ENCRYPTED_FILE_NAME, KEY, MODE)
    print(f"Fichier {FILE_NAME} chiffré en {ENCRYPTED_FILE_NAME}")

    # Déchiffrer le fichier
    decrypt_file(ENCRYPTED_FILE_NAME, DECRYPTED_FILE_NAME, KEY, MODE)
    print(f"Fichier {ENCRYPTED_FILE_NAME} déchiffré en {DECRYPTED_FILE_NAME}")

    # Calculer et afficher le SHA-256 du fichier déchiffré
    decrypted_sha256_hash = calculate_sha256(DECRYPTED_FILE_NAME)
    print(f"SHA-256 du fichier déchiffré {DECRYPTED_FILE_NAME}: {decrypted_sha256_hash}")

    # Vérifier que les hashes sont identiques
    if sha256_hash == decrypted_sha256_hash:
        print("Les hashes sont identiques, le déchiffrement a réussi.")
    else:
        print("Les hashes sont différents, le déchiffrement a échoué.")

if __name__ == "__main__":
    main()