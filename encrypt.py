import base64
# import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = input('Please insert your password: ')

# salt = os.urandom(16)
salt = input('Please insert your salt: ')
bytes_salt = bytes(salt, 'utf-8')
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=bytes_salt,
    iterations=100000,
)

key = base64.urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))
f = Fernet(key)

secret = input('Please insert the string that you want to encrypt: ')
token = f.encrypt(bytes(secret, 'utf-8'))
print(f"Your token is:\n{token}")
