"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import util

def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def resolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid
            elif res.startswith("[POINTER]"):
                uid = res[10:]
            else:
                raise IntegrityError()



    def upload(self, name, value):
        # Replace with your implementation
        uid = self.crypto.cryptographic_hash(self.resolve(path_join(self.username, name)), "SHA256")
        symmetric_key = self.crypto.get_random_bytes(32)
        try:
            asymmetric_key = self.crypto.asymmetric_encrypt(symmetric_key, self.private_key.publickey())
        except:
            raise IntegrityError()
        if self.storage_server.get(self.username) is not None:
            asymmetric_key = self.storage_server.get(self.username)
            try:
                symmetric_key = self.crypto.asymmetric_decrypt(asymmetric_key, self.private_key)
            except:
                raise IntegrityError()
        else:
            self.storage_server.put(self.username, asymmetric_key)
        try:
            encrypted_name = self.crypto.symmetric_encrypt(uid, symmetric_key, 'AES')
            encrypted_name = util.to_json_string(encrypted_name)
        except:
            raise IntegrityError()
        try:
            value = self.crypto.symmetric_encrypt(value, symmetric_key, 'AES')
        except:
            raise IntegrityError()
        self.storage_server.put(encrypted_name, value)
        # raise NotImplementedError

    def download(self, name):
        # Replace with your implementation
        uid = self.crypto.cryptographic_hash(self.resolve(path_join(self.username, name)), "SHA256")
        if self.storage_server.get(self.username) is None:
            return None
        else: 
            asymmetric_key = self.storage_server.get(self.username)
            try:
                symmetric_key = self.crypto.asymmetric_decrypt(asymmetric_key, self.private_key)
            except:
                raise IntegrityError()
        try:
            encrypted_name = self.crypto.symmetric_encrypt(uid, symmetric_key, 'AES')
            encrypted_name = util.to_json_string(encrypted_name)
        except:
            raise IntegrityError()
        resp = self.storage_server.get(encrypted_name)
        try:
            resp = self.crypto.symmetric_decrypt(resp, symmetric_key, 'AES')
        except:
            return None
        if resp is None:
            return None
        return resp
    # raise NotImplementedError

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
