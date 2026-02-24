from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

key = b"YELLOW SUBMARINE"
with open("7.txt", "r") as f:
    ciphertext = base64.b64decode(f.read())
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
print(plaintext.decode('utf-8'))