import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class RSAcrypto():
    def __init__(self):
        #generate RSA private key, for decryption
        self.private_key = rsa.generate_private_key(public_exponent = 65537, 
                                                    key_size = 4096, 
                                                    backend = default_backend)
        
        #generating RSA public key from private key, for encryption
        self.public_key = self.private_key.public_key()

    #encryption magic done here
    def encrypt(self, plain):
        self.cipher_text_bytes = self.public_key.encrypt(plaintext = plain.encode("utf-8"),
                                                            padding = padding.OAEP(
                                                                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                                                                algorithm = hashes.SHA512(),
                                                                label = None))
        self.cipher_text = base64.b64encode(self.cipher_text_bytes).decode("utf-8")

    def encrypted(self):
        return self.cipher_text

    #decryption magic done here
    def decrypt(self, cipher):
        self.decrypted_cipher_text_bytes = self.private_key.decrypt(
            ciphertext = base64.b64decode(self.cipher_text),
            padding = padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA512(),
                label = None))
        self.decipher_text = self.decrypted_cipher_text_bytes.decode("utf-8")

    def decrypted(self):
        return self.decipher_text

    #this for decryption private key
    def get_private_key(self):
        return self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode("utf-8")

    #this for decryption of public key
    def get_public_key(self):
        return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1).decode("utf-8")

enc = RSAcrypto()

#for both public and private key
print(enc.get_public_key())
print(enc.get_private_key())

#any string to be encrypt here
enc.encrypt("any_text_to_encrypt")
print(f"encrypted:\n{enc.encrypted()}")

#any string to be decrypt here
enc.decrypt(enc.encrypted())
print(f"decrypted:\n{enc.decrypted()}")

