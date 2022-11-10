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
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization

def GENERATE_DH():
        priv_key = ec.generate_private_key(ec.SECP256R1)
        return priv_key, priv_key.public_key()

def DH(dh_pair, dh_pub):
        return dh_pair['sk'].exchange(ec.ECDH(), dh_pub)

def KDF_RK(rk, dh_out):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=rk, backend=default_backend()
        )
        key = kdf.derive(dh_out)
        return key[0:32], key[32:64]

def KDF_CK(ck):
        hmac1 = hmac(ck, hashes.SHA256)
        hmac2 = hmac(ck, hashes.SHA256)
        # bytes1 = {'1', 'ascii'}
        # bytes2 = {'2', 'ascii'}
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
        # return {'dh' = dh_pair, 'pn' = pn, 'n' = n}

    class MessengerServer:
        def __init__(self, server_signing_key, server_decryption_key):
            self.server_signing_key = server_signing_key
            self.server_decryption_key = server_decryption_key

        def decryptReport(self, ct):
            raise Exception("not implemented!")
            return

        def signCert(self, cert):
            cert['public_key'] = cert['public_key'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            serialized_cert = pickle.dumps(cert)
            signature = self.server_signing_key.sign(
                serialized_cert,
                ec.ECDSA(hashes.SHA256())
            )
            return signature

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
            ec.SECP256R1()
        )
        pub_key = priv_key.public_key()
        key_to_share = priv_key.exchange(ec.ECDH(), pub_key)
        #might actually want my public key to be key_to_share
        return {'private_key': priv_key, 'public_key': pub_key}
    #End my functions
      
    def generateCertificate(self):
        #Gigi's code is commented
        #sk, pk = GENERATE_DH()
        #self.sk = sk
        #self.pk = pk
        #certificate = {'name': self.name, 'public_key': DH_keys['public_key']}
        #raise Exception("not implemented!")
        #return
        
        #begin Ella's code
        DH_keys = self.generateDH()
        certificate = {'name': self.name, 'public_key': DH_keys['public_key']}
        self.conns[self.name] = {'private_key': DH_keys['private_key'], 'public_key': DH_keys['public_key']}
        #raise Exception("not implemented!")
        return certificate

    def receiveCertificate(self, certificate, signature):
        #verify sig
        certificate['public_key'] = certificate['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        serialized_cert = pickle.dumps(certificate)
        #serialized_cert = pickle.dumps(certificate)

        #check this verify function
        try:
            self.server_signing_key.public_key().verify(signature, serialized_cert, ec.ECDSA(hashes.SHA256()))
        except:
            raise Exception("the signature on the certificate for this user isn't valid")
            return
        else:
            #certificate['public_key'].verify(signature, serialized_cert, ec.ECDSA(hashes.SHA256()))
            #store the cert
            self.certs[certificate['name']] = certificate
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











