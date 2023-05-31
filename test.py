import base64
import os

encryption_key = base64.urlsafe_b64encode(os.urandom(32))

print(len('Q4bOALstbrq0hdvukj5fdz8xR9V-J-w_yWuGYX8vCuU='))
