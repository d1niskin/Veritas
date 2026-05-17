import os
import secrets
import string
from cryptography.fernet import Fernet
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

key_from_env = os.getenv("ENCRYPTION_KEY")
if not key_from_env:
    raise ValueError("Критическая ошибка: ENCRYPTION_KEY не найден в .env")

ENCRYPTION_KEY = key_from_env.encode('utf-8')
cipher_suite = Fernet(ENCRYPTION_KEY)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def generate_pin(length=6):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

def get_password_hash(password: str) -> str:
    safe_password = password[:72]
    return pwd_context.hash(safe_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    safe_password = plain_password[:72]
    try:
        return pwd_context.verify(safe_password, hashed_password)
    except ValueError:
        return False

def encrypt_text(text: str) -> str:
    return cipher_suite.encrypt(text.encode('utf-8')).decode('utf-8')

def decrypt_text(encrypted_text: str) -> str:
    return cipher_suite.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')