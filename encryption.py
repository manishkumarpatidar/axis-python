from base64 import b64encode, b64decode
from Crypto.Cipher import AES

class AESCipher:

    class InvalidBlockSizeError(Exception):
        """Raised for invalid block sizes"""
        pass

    def __init__(self, key):
        self.key = key
        self.iv = bytes(key[0:16], 'utf-8')

    def __pad(self, text):
        text_length = len(text)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def __unpad(self, text):
        pad = ord(text[-1])
        return text[:-pad]

    def encrypt( self, raw ):
        raw = self.__pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return b64encode(cipher.encrypt(raw)).decode("utf-8")

    def decrypt( self, enc ):
        enc = b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        r = cipher.decrypt(enc)  # type: bytes
        return self.__unpad(r.decode("utf-8", errors='strict'))
    