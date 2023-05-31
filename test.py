import base64
import os

encryption_key = base64.urlsafe_b64encode(os.urandom(32))

print(encryption_key)
