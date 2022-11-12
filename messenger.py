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

#change this to the GENERATE_DH in the Messenger_Client object
def GENERATE_DH():
        priv_key = ec.generate_private_key(ec.SECP256R1)
        return priv_key, priv_key.public_key()

def DH(dh_pair, dh_pub):
        return dh_pair['sk'].exchange(ec.ECDH(), dh_pub)

def KDF_RK(rk, dh_out):
        def KDF_RK(rk, dh_out):
        serialized_root_key = rk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        input = serialized_root_key + dh_out
        h = hmac.HMAC(rk, hashes.SHA256())
        key = h.update(input)
        length = len(key/2)
        kdf_key = key[0:length]
        start_len = length + 1
        output_key = key[start_len : len(key)]
        return({'root_key': kdf_key, 'output_key': output_key})
        #kdf = PBKDF2HMAC(
        #    algorithm=hashes.SHA256(), length=32, salt=rk, backend=default_backend()
        #)
        #key = kdf.derive(dh_out)
        #return key[0:32], key[32:64]

def KDF_CK(ck):
        def KDF_CK(ck):
        serialized_chain_key = ck.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        h = hmac.HMAC(ck, hashes.SHA256())
        key = h.update(serialized_chain_key)
        length = len(key/2)
        kdf_key = key[0:length]
        start_len = length + 1
        output_key = key[start_len : len(key)]
        return({'chain_key': kdf_key, 'output_key': output_key})
    
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
        cipher_text = ct['cipher_text']
        private_key, public_key = GENERATE_DH()
        keys = {'sk': private_key, 'pk': public_key}
        v = DH(keys, self.server_decryption_key)
        v = ct['public_key'] ** self.server_decryption_key
        v = v.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        serialized_dec_key = self.server_decryption_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        concat_keys = v + serialized_dec_key
        digest = hashes.Hash(hashes.SHA256()) 
        digest.update(concat_keys)
        key = digest.finalize()
        plain_text = DECRYPT(key, ct, None)
        return {'name': ct['name'], 'plain_text': plain_text}

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

    def DH(dh_pair, dh_pub):
        shared_key = dh_pair['secret_key'].exchange(ec.ECDH(), dh_pub)
        hash = hashes.Hash(hashes.SHA256())
        serialized_key = shared_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        serialized_public_key = dh_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        serialized_key += serialized_public_key
        hash.update(serialized_key)
        hashed = hash.finalize()
        return hashed
    #End my functions
      
    def generateCertificate(self):
        def generateCertificate(self):
        private_key, public_key = GENERATE_DH()
        certificate = {'name': self.name, 'public_key': public_key}
        self.conns[self.name] = {'private_key': private_key, 'public_key': public_key}
        return certificate

    def receiveCertificate(self, certificate, signature):
        #verify sig
        certificate['public_key'] = certificate['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        serialized_cert = pickle.dumps(certificate)
        self.server_signing_pk.verify(signature, serialized_cert, ec.ECDSA(hashes.SHA256()))
        self.certs[certificate['name']] = certificate

    def sendMessage(self, name, message):

        raise Exception("not implemented!")
        return

    def receiveMessage(self, name, header, ciphertext):

        raise Exception("not implemented!")
        return

    def report(self, name, message):
        private_key, public_key = GENERATE_DH()
        keys = {'sk': private_key, 'pk': public_key}
        enc_key = DH(keys, self.server_encryption_pk)
        message_bytes = bytes(message, 'ascii') * enc_key
        cipher_text = ENCRYPT(enc_key, message, None)
        return {'name': name, 'cipher_text': cipher_text}











