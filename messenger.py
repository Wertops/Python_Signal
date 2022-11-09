import os
import pickle
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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

        #My added parameters:
        self.p = 999331
        self.g = 13

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

        DH_keys = generateDH(self);
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










