# from Cryptodome.Cipher import AES
# from Cryptodome.Hash import SHA256
# from Cryptodome.Random import get_random_bytes
# from Cryptodome.Util.Padding import pad, unpad

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

if __name__ == '__main__':

    key = b'\x00' * 16
    data = "hello world".encode('utf-8') + b'\x00' * 5
    iv = b'\x00' * 16
    aes = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = aes.encrypt(data).hex()
    print("Ciphertext:", ciphertext)
