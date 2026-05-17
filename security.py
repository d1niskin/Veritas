import os
import secrets
import string
from cryptography.fernet import Fernet
import bcrypt
from dotenv import load_dotenv

load_dotenv()

key_from_env = os.getenv("ENCRYPTION_KEY")
if not key_from_env:
    raise ValueError("Критическая ошибка: ENCRYPTION_KEY не найден в .env")

ENCRYPTION_KEY = key_from_env.encode('utf-8')
cipher_suite = Fernet(ENCRYPTION_KEY)

def generate_pin(length=6):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

def get_password_hash(password: str) -> str:
    clean_pwd = str(password).strip().replace(" ", "")
    pwd_bytes = clean_pwd.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        clean_pwd = str(plain_password).strip().replace(" ", "")
        pwd_bytes = clean_pwd.encode('utf-8')[:72]
        hashed_bytes = str(hashed_password).strip().encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hashed_bytes)
    except Exception as e:
        print(f"[Crypto System Error] Ошибка bcrypt: {e}")
        return False

def encrypt_text(text: str) -> str:
    return cipher_suite.encrypt(text.encode('utf-8')).decode('utf-8')

def decrypt_text(encrypted_text: str) -> str:
    return cipher_suite.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')