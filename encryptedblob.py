#REMEMBER TO START THE VENV

import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import imexceptions


class EncryptedBlob:

    # the constructor
    def __init__(self, plaintext=None, confkey=None, authkey=None): 
        self.plaintext = plaintext
        self.ivBase64 = None
        self.ciphertextBase64 = None
        self.macBase64 = None

        if plaintext is not None:
            self.ivBase64, self.ciphertextBase64, self.macBase64 = self.encryptThenMAC(confkey, authkey, plaintext)



    # encrypts the plaintext and adds a SHA256-based HMAC
    # using an encrypt-then-MAC solution
    def encryptThenMAC(self,confkey,authkey,plaintext):
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY ENCRYPT 
        # AND GENERATE A SHA256-BASED HMAC BASED ON THE 
        # confkey AND authkey

        # pad the plaintext to make AES happy
        plaintextPadded = pad(bytes(plaintext,'utf-8'),16) 
        iv = get_random_bytes(16)
        cipher = AES.new(confkey, AES.MODE_CBC, iv)  #library automatically creates random IV
        ciphertext = cipher.encrypt(plaintextPadded)

        concatenated_keys_bytes = authkey + confkey

        mac = HMAC.new(concatenated_keys_bytes, digestmod=SHA256)
        mac.update(iv + ciphertext) #not sure if I need this or just HMAC based on keys
        mac_digest = mac.digest() #get the HMAC value

        # DON'T CHANGE THE BELOW.
        # What we're doing here is converting the iv, ciphertext,
        # and mac (which are all in bytes) to base64 encoding, so that it 
        # can be part of the JSON EncryptedIM object
        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(mac_digest).decode("utf-8") 
        return ivBase64, ciphertextBase64, macBase64


    def decryptAndVerify(self,confkey,authkey,ivBase64,ciphertextBase64,macBase64):
        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        receivedMac = base64.b64decode(macBase64)
        
        # TODO: MODIFY THE CODE BELOW TO ACTUALLY DECRYPT
        # IF IT DOESN'T DECRYPT, YOU NEED TO RAISE A 
        # FailedDecryptionError EXCEPTION
        try:
            cipher = AES.new(confkey, AES.MODE_CBC, iv)
            self.plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except:
            raise imexceptions.FailedDecryptionError("Decryption error!")

        # TODO: hint: in encryptThenMAC, I padded the plaintext.  You'll
        # need to unpad it.
        # See https://pycryptodome.readthedocs.io/en/v3.11.0/src/util/util.html#crypto-util-padding-module

        # so, this next line is definitely wrong.  :)

        # TODO: DON'T FORGET TO VERIFY THE MAC!!!
        # IF IT DOESN'T VERIFY, YOU NEED TO RAISE A
        # FailedAuthenticationError EXCEPTION 
        concatenated_keys_bytes = authkey + confkey

        computedMac = HMAC.new(concatenated_keys_bytes, digestmod=SHA256)
        computedMac.update(iv + ciphertext) #not sure if I need this or just HMAC based on keys
        computedMac_digest = computedMac.digest() #get the HMAC value
        if (computedMac_digest != receivedMac):
            raise imexceptions.FailedAuthenticationError("Computed HMAC does not match received HMAC!")
               

        return self.plaintext.decode('utf-8')
