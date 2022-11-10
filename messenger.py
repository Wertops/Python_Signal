import os
import pickle
import string
import hashlib
import random
import re
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
        sk, pk = GENERATE_DH()
        self.sk = sk
        self.pk = pk
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
        parameters = dh.generate_parameters(generator= 2, key_size= 2048)
        server_pk = parameters.generate_private_key()
        person_pk = parameters.generate_private_key()
        shared_key = server_pk.exchange(person_pk.public_key)
        return server_pk, shared_key

    def DH(dh_pair, dh_pub):
        
        return

    def KDF_RK(rk, dh_out):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=rk, backend=default_backend()
        )
        key = kdf.derive(dh_out)
        return key

    def KDF_CK(ck):
        h = hmac(ck, hashes.SHA256)
        return h
    
    def ENCRYPT(mk, plaintext, assoc_data):
        aesgcm = AESGCM(mk)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce= nonce, data= plaintext, associated_data= assoc_data)
        return ct

    def DECRYPT(mk, ciphertext, assoc_data):
        aesgcm = AESGCM(mk)
        nonce = os.urandom(12)
        pt = aesgcm.decrypt(nonce= nonce, data= ciphertext, associated_data= assoc_data)
        return pt

    def HEADER(dh_pair, pn, n):
        return










