# from Cryptodome.Cipher import AES
# from Cryptodome.Hash import SHA256
# from Cryptodome.Random import get_random_bytes
# from Cryptodome.Util.Padding import pad, unpad

from wolfcrypt.ciphers import Aes, MODE_CBC

if __name__ == '__main__':

    key = b'\x00' * 16
    data = b'\x00' * 16
    iv = b'\x00' * 16
    aes = Aes(key, MODE_CBC, iv)
    ciphertext = aes.encrypt(data).hex()
    print("Ciphertext:", ciphertext)
