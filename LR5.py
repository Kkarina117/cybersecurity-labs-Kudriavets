import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

KDF_ITERATIONS = 480000
PRIVATE_KEY_SALT_SIZE = 16
AES_KEY_SIZE = 32
AESGCM_NONCE_SIZE = 12

def derive_key_from_password(password: str, salt: bytes, iterations: int = KDF_ITERATIONS, length: int = AES_KEY_SIZE) -> bytes:
    """Виводить симетричний ключ з паролю через PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def generate_key_pair_protected(password: str) -> Tuple[bytes, bytes]:

    # генеруємо RSA
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # серіалізація приватного ключа у PEM (без пароля, бо ми будемо шифрувати його самі)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # серіалізація публічного ключа
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # шифруємо приватний PEM симетрично, використовуючи пароль + PBKDF2
    salt = os.urandom(PRIVATE_KEY_SALT_SIZE)
    aes_key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(AESGCM_NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, private_pem, None)  # додаткові дані = None

    # упаковка: salt || nonce || ciphertext
    encrypted_blob = salt + nonce + ciphertext
    return public_pem, encrypted_blob


def load_private_key_from_blob(encrypted_blob: bytes, password: str):

    try:
        salt = encrypted_blob[:PRIVATE_KEY_SALT_SIZE]
        nonce = encrypted_blob[PRIVATE_KEY_SALT_SIZE:PRIVATE_KEY_SALT_SIZE + AESGCM_NONCE_SIZE]
        ciphertext = encrypted_blob[PRIVATE_KEY_SALT_SIZE + AESGCM_NONCE_SIZE:]

        aes_key = derive_key_from_password(password, salt)
        aesgcm = AESGCM(aes_key)
        private_pem = aesgcm.decrypt(nonce, ciphertext, None)

        private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
        return private_key
    except Exception as e:
        # можливі причини: невірний пароль, пошкоджені дані, інші помилки
        return None


def load_public_key(public_pem: bytes):
    return serialization.load_pem_public_key(public_pem, backend=default_backend())

def encrypt_message_hybrid(message: str, recipient_public_pem: bytes) -> str:

    public_key = load_public_key(recipient_public_pem)
    # 1) симетричний ключ
    aes_key = os.urandom(AES_KEY_SIZE)
    # 2) AES-GCM шифрування повідомлення
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(AESGCM_NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)  # містить і таг

    # 3) зашифрувати симетричний ключ RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # 4) пакет у вигляді base64 частин
    parts = [
        base64.b64encode(encrypted_key).decode('utf-8'),
        base64.b64encode(nonce).decode('utf-8'),
        base64.b64encode(ciphertext).decode('utf-8'),
    ]
    return ':'.join(parts)


def decrypt_message_hybrid(encrypted_package_b64: str, encrypted_private_blob: bytes, password: str) -> str:

    # спочатку відновити приватний ключ
    private_key = load_private_key_from_blob(encrypted_private_blob, password)
    if private_key is None:
        return "ПОМИЛКА: невірний пароль або пошкоджений приватний ключ."

    try:
        enc_key_b64, nonce_b64, ciphertext_b64 = encrypted_package_b64.split(':')
        encrypted_key = base64.b64decode(enc_key_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # RSA-розшифрування симетричного ключа
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # AES-GCM розшифрування
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"ПОМИЛКА при розшифруванні: {e}"

def run_demo():
    pwd = input("Пароль для генерації ключа → ").strip()
    if not pwd:
        print("Немає пароля — стоп.")
        return

    public_pem, encrypted_private_blob = generate_key_pair_protected(pwd)

    # Відображаємо тільки важливе
    pub = public_pem.decode()
    short_pub = pub.split("\n")[1][:60] + "..."   # лише фрагмент ключа

    print(f"\nПублічний ключ: {short_pub}")

    msg = input("\nТекст → ")
    encrypted = encrypt_message_hybrid(msg, public_pem)

    print(f"\nЗашифровано:\n{encrypted}")

    pwd2 = input("\nПароль для розшифрування → ").strip()
    decrypted = decrypt_message_hybrid(encrypted, encrypted_private_blob, pwd2)

    print(f"\nРозшифровано:\n{decrypted}")

    print("\nПеревірка неправильної авторизації:")
    print(decrypt_message_hybrid(encrypted, encrypted_private_blob, 'wrong'))

if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\nЗавершено користувачем.")
