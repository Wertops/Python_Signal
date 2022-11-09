import os
import pickle
import string
import hashlib
import random
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey, Ed25519PrivateKey


class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        raise Exception("not implemented!")
        return

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}


        #My functions
        def generateDH(self):
            priv_key = ec.generate_private_key(
                ec.SECP256R1
            )
            pub_key = priv_key.public_key()
            key_to_share = priv_key.exchange(ec.ECDH(), pub_key)
            #might actually want my public key to be key_to_share
            return {'private_key': priv_key, 'public_key': pub_key}

    def generateCertificate(self):

        DH_keys = GENERATE_DH(self)
        certificate = {'name': self.name, 'public_key': DH_keys['public_key']}

        raise Exception("not implemented!")
        return

    def receiveCertificate(self, certificate, signature):
        raise Exception("not implemented!")
        return

    def sendMessage(self, name, message):
        raise Exception("not implemented!")
        return

    def receiveMessage(self, name, header, ciphertext):
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        raise Exception("not implemented!")
        return

    def GENERATE_DH():
        
        return

    def DH(dh_pair, dh_pub):
        return

    def KDF_RK(rk, dh_out):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=rk, backend=default_backend()
        )
        key = kdf.derive(dh_out)
        return key

    def KDF_CK(ck):
        return
    
    def ENCRYPT(mk, plaintext, assoc_data):
        return

    def DECRYPT(mk, ciphertext, assoc_data):
        return

    def HEADER(dh_pair, pn, n):
        return










