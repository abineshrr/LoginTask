#import os

# Generate a secure random byte array
#key_size_bytes = 32  # 32 bytes = 256 bits (recommended for AES-256)
#secret_key = os.urandom(key_size_bytes)

# Convert the byte array to a hexadecimal string
#secret_key_hex = secret_key.hex()

#print("Secret Key:", secret_key_hex)
#-------------------------

#
# # --------------------------------
# import bcrypt
# from Crypto.Util.Padding import unpad, pad
# from Crypto.Cipher import AES
# from cryptography.fernet import Fernet
# from passlib.context import CryptContext
# from base64 import b64encode, b64decode
# import binascii

# encoded_password1 = bcrypt.hashpw(b"string123", bcrypt.gensalt())
# print(encoded_password1)
# demo = bcrypt.checkpw(b"string123", encoded_password1)
# print(demo)
