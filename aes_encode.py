# -*- coding: utf-8 -*-
"""
# @Time    : 2023/7/16 6:34 PM
---------
@author: neolp
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode



class AES_DECODE():

    def encrypt(self, plain_text, key):
        #加密
        cipher = AES.new(key, AES.MODE_CBC)
        cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
        iv = b64encode(cipher.iv).decode()
        encrypted_text = b64encode(cipher_text).decode()
        return iv + encrypted_text

    def decrypt(self, cipher_text, key):
        # 解密的内容
        iv = b64decode(cipher_text[:24])
        cipher_text = b64decode(cipher_text[24:])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
        return decrypted_text.decode()

    # 生成随机的128位密钥
    # key = get_random_bytes(16)
    # print(key)
    # 一定要选择长度为16的字符串，可以自己构建。
    key = "1" * 16

    key = key.encode()


if __name__ == '__main__':

    aes_decode = AES_DECODE()


    # 选择加密还是解密
    type_key = input("输入1加密内容，输入2解密内容 请输入你的值：")

    if type_key == '1':
        for i in range(1, 100):
            # 要加密的明文
            plain_text = input("请输入你加密的值：")
            encrypted_text = aes_decode.encrypt(plain_text, AES_DECODE.key)
            print("加密后的结果:", encrypted_text)
            decrypted_text = aes_decode.decrypt(encrypted_text, AES_DECODE.key)
            print("加密文本解密后的结果:", decrypted_text)

    elif type_key == '2':
        for i in range(1, 100):
            # 要解密的内容
            plain_text = input("请输入你解密的值：")
            decrypted_text = aes_decode.decrypt(plain_text, AES_DECODE.key)
            print("解密后的结果:", decrypted_text)
    else:
        print('输入类型错误')


