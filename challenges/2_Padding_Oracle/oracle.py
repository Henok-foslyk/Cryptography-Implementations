from Crypto.Cipher import AES
from Crypto.Util import Padding
from base64 import b64decode

PADDING_ERROR = True
PADDING_OK = False

def oracle(ivciphertext):
    key = b64decode(b'WU9VX0FSRV9DSEVBVElORw==')
    iv = ivciphertext[:AES.block_size]
    ciphertext = ivciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        padded_plaintext = cipher.decrypt(ciphertext)
    except ValueError:
        return PADDING_ERROR

    try:
        plaintext = Padding.unpad(padded_plaintext, AES.block_size, style='iso7816')
        return PADDING_OK
    except ValueError:
        return PADDING_ERROR
