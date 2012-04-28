#!/usr/bin/env python

 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

"""
DDTB crypto functionality library class
"""

from hashlib import sha256
from Crypto.Cipher import AES
import random

class TBCrypt(object):

    padding = chr(8)

    def encryptPassword(self, iv, plaintext, key):
        """Return AES256 encrypted password
        Read master password and take SHA256-hash out of it. This hash
        is guaranteed to be 256 bits which is correct AES encryption
        key size. The hash is used as the encryption key.

        Given input is encrypted using the key and ciphertext
        is returned.
        """
#        plaintext = plaintext.encode('utf_8')
        plaintext = plaintext + self.padding*(16 - (len(plaintext)%16))
        aes_key = sha256(key).digest()
        aes_mode = AES.MODE_CBC
        aes_encryptor = AES.new(aes_key, aes_mode, iv)
#        ciphertext = aes_encryptor.encrypt(plaintext)
#        return ciphertext
        return aes_encryptor.encrypt(plaintext)

    def decryptPassword(self, iv, ciphertext, key):
#        ciphertext = ciphertext.encode('utf_8')
        aes_key = sha256(key).digest()
        aes_mode = AES.MODE_CBC
        aes_decryptor = AES.new(aes_key, aes_mode, iv)
        plaintext = aes_decryptor.decrypt(ciphertext)
        return plaintext.split(self.padding, 1)[0]

    def encryptWithoutIV(self, plaintext, key):
        plaintext = plaintext + self.padding*(16 - (len(plaintext)%16))
        aes_key = sha256(key).digest()
        aes_mode = AES.MODE_CBC
        aes_encryptor = AES.new(aes_key, aes_mode)
        return aes_encryptor.encrypt(plaintext)

    def decryptWithoutIV(self, ciphertext, key):
        aes_key = sha256(key).digest()
        aes_mode = AES.MODE_CBC
        aes_decryptor = AES.new(aes_key, aes_mode)
        plaintext = aes_decryptor.decrypt(ciphertext)
        return plaintext.split(self.padding, 1)[0]

    def random_bytes(self, size):
        return "".join(chr(random.randrange(0, 256)) for i in xrange(size))

    def get_new_iv(self):
        return self.random_bytes(16)

    if __name__ == "__main__":
        print "This is a library class."
        exit(0)
