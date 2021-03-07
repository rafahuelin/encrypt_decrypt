import base64
import binascii
# import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = bytes(input('Please insert your password: '), 'utf-8')

# salt = os.urandom(16)
salt = input('Please insert your salt: ')
bytes_salt = bytes(salt, 'utf-8')
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=bytes_salt,
    iterations=100000,
)

key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)

token = input('Please enter token: ')

secret = f.decrypt(bytes(token, 'utf-8'))
secret_string = secret.decode('utf-8')
print(f"Your secret string is:\n{secret_string}")