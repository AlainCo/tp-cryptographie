from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Constantes
FILE_NAME = "input.txt"
ENCRYPTED_FILE_NAME = "work/encrypted.bin"
DECRYPTED_FILE_NAME = "work/decrypted.txt"
SIGNED_FILE_NAME = "work/signed.bin"
SIGNATURE_FILE_NAME = "work/signature.bin"
PRIVATE_KEY_FILE = "work/private_key.pem"
PUBLIC_KEY_FILE = "work/public_key.pem"

ALICE_PRIVATE_KEY_FILE = "work/alice.private_key.pem"
ALICE_PUBLIC_KEY_FILE = "work/alice.public_key.pem"
BOB_PRIVATE_KEY_FILE = "work/bob.private_key.pem"
BOB_PUBLIC_KEY_FILE = "work/bob.public_key.pem"


KEY_SIZE = 2048  # Taille de la clé RSA
SYMMETRIC_KEY_SIZE = 32  # Taille de la clé symétrique AES-256

def generate_rsa_keys(private_key_file,public_key_file):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    with open(private_key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(public_key_file, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Clés RSA sauvegardées vers  {private_key_file} et {public_key_file}")
    return private_key, public_key

def load_rsa_private_key(private_key_file):
    # Charger la clé privée
    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    print(f"Clés privée RSA chargée depuis {private_key_file} ")
    return private_key
def load_rsa_public_key(public_key_file):
    # Charger la clé publique
    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    print(f"Clés publique RSA chargée depuis {public_key_file}")
    return public_key

def encrypt_file_rsa(input_file, output_file, public_key):
    # Générer une clé symétrique AES
    symmetric_key = os.urandom(SYMMETRIC_KEY_SIZE)

    # Chiffrer la clé symétrique avec la clé publique RSA
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Chiffrer le fichier avec la clé symétrique AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(input_file, 'rb') as f:
        data = f.read()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Sauvegarder l'IV, la clé chiffrée et les données chiffrées
    with open(output_file, 'wb') as out_f:
        out_f.write(iv + encrypted_key + encrypted_data)

def decrypt_file_rsa(input_file, output_file, private_key):
    with open(input_file, 'rb') as f:
        iv = f.read(16)
        encrypted_key = f.read(KEY_SIZE // 8)  
        encrypted_data = f.read()

    # Déchiffrer la clé symétrique avec la clé privée RSA
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Déchiffrer le fichier avec la clé symétrique AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as out_f:
        out_f.write(data)

def sign_file(input_file, signature_file, private_key):
    with open(input_file, 'rb') as f:
        data = f.read()
        # Avec le padding "PSS", la méthode sign effectue automatiquement 
        # le hachage des données avec SHA-256
        # avant de les signer avec la clé privée RSA.
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        with open(signature_file, 'wb') as sig_f:
            sig_f.write(signature)

def verify_signature(input_file, signature_file, public_key):
    with open(input_file, 'rb') as f:
        data = f.read()
    with open(signature_file, 'rb') as sig_f:
        signature = sig_f.read()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def test_simple():
    # Générer les clés RSA, si besoin
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        #charger les clés RSA
        public_key = load_rsa_public_key(PUBLIC_KEY_FILE)
        private_key = load_rsa_private_key(PRIVATE_KEY_FILE)
    else:
        private_key, public_key = generate_rsa_keys(PRIVATE_KEY_FILE,PUBLIC_KEY_FILE)
    
    
    # Chiffrer le fichier avec la clé publique RSA et une clé symétrique AES
    encrypt_file_rsa(FILE_NAME, ENCRYPTED_FILE_NAME, public_key)
    print(f"Fichier {FILE_NAME} chiffré en {ENCRYPTED_FILE_NAME}")

    # Déchiffrer le fichier avec la clé privée RSA et la clé symétrique AES
    decrypt_file_rsa(ENCRYPTED_FILE_NAME, DECRYPTED_FILE_NAME, private_key)
    print(f"Fichier {ENCRYPTED_FILE_NAME} déchiffré en {DECRYPTED_FILE_NAME}")

    # Signer le fichier avec la clé privée RSA
    sign_file(DECRYPTED_FILE_NAME, SIGNATURE_FILE_NAME, private_key)
    print(f"Fichier {DECRYPTED_FILE_NAME} signé et signature sauvegardée dans {SIGNATURE_FILE_NAME}")

    # Vérifier la signature avec la clé publique RSA
    is_valid = verify_signature(DECRYPTED_FILE_NAME, SIGNATURE_FILE_NAME, public_key)
    if is_valid:
        print("La signature est valide.")
    else:
        print("La signature est invalide.")
        
def test_alice_bob():
    if os.path.exists(ALICE_PRIVATE_KEY_FILE) and os.path.exists(ALICE_PUBLIC_KEY_FILE):
        #charger les clés RSA
        alice_public_key = load_rsa_public_key(ALICE_PUBLIC_KEY_FILE)
        alice_private_key = load_rsa_private_key(ALICE_PRIVATE_KEY_FILE)
    else:
        alice_private_key, alice_public_key = generate_rsa_keys(ALICE_PRIVATE_KEY_FILE,ALICE_PUBLIC_KEY_FILE)
    if os.path.exists(BOB_PRIVATE_KEY_FILE) and os.path.exists(BOB_PUBLIC_KEY_FILE):
        #charger les clés RSA
        bob_public_key = load_rsa_public_key(BOB_PUBLIC_KEY_FILE)
        bob_private_key = load_rsa_private_key(BOB_PRIVATE_KEY_FILE)
    else:
        bob_private_key, bob_public_key = generate_rsa_keys(BOB_PRIVATE_KEY_FILE,BOB_PUBLIC_KEY_FILE)
    # je suis alice
    # Chiffrer le fichier avec la clé publique RSA de BOB et une clé symétrique AES aléatoire puis chiffrée
    encrypt_file_rsa(FILE_NAME, ENCRYPTED_FILE_NAME, bob_public_key)
    print(f"Fichier {FILE_NAME} chiffré en {ENCRYPTED_FILE_NAME}")
    
    sign_file(DECRYPTED_FILE_NAME, SIGNATURE_FILE_NAME, alice_private_key)
    print(f"Fichier {DECRYPTED_FILE_NAME} signé et signature sauvegardée dans {SIGNATURE_FILE_NAME}")
    
    # je suis bob
    # Déchiffrer le fichier avec la clé privée RSA de BOB et la clé symétrique AES chiffére dans le fichier
    decrypt_file_rsa(ENCRYPTED_FILE_NAME, DECRYPTED_FILE_NAME, bob_private_key)
    print(f"Fichier {ENCRYPTED_FILE_NAME} déchiffré en {DECRYPTED_FILE_NAME}")
    
     # Vérifier la signature avec la clé publique RSA
    is_valid = verify_signature(DECRYPTED_FILE_NAME, SIGNATURE_FILE_NAME, alice_public_key)
    if is_valid:
        print("La signature est valide.")
    else:
        print("La signature est invalide.")

if __name__ == "__main__":
    try:
        test_alice_bob()
    except Exception as e:
        print(f"exception : {e}")
