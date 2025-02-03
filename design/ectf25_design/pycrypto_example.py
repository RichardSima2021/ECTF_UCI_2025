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


    # AES example
    data = pad('1111111111111111'.encode(), AES.block_size)

    aes_key = get_random_bytes(16)

    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(data)

    decry = AES.new(aes_key, AES.MODE_CBC, cipher.iv)
    plaintext = unpad(decry.decrypt(ciphertext), AES.block_size)

    print(ciphertext)
    print(plaintext)


    # SHA256 example
    data = b"hello"
    hash = SHA256.new()
    hash.update(data)
    hashed_res = hash.hexdigest()
    print(hashed_res)
