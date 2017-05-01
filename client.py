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
        try:
            if self.storage_server.get(self.username + "/directory") is not None:
                EDictionaryAndSymmKeys = util.from_json_string(self.storage_server.get(self.username + "/directory"))
                # EDictionary = SE({name : fileID})
                EDictionary = EDictionaryAndSymmKeys[0]
                # ESymms = AE(symmKey1, symmKey2)
                ESymms = EDictionaryAndSymmKeys[1]
                # symmKeysYay = (symmKey1, symmKey2)
                symmKeysYay = self.crypto.asymmetric_decrypt(ESymms, self.private_key)
                # dictionaryYay = {name : fileID}
                dictionaryYayString = self.crypto.symmetric_decrypt(EDictionary, symmKeysYay, 'AES')
                dictionaryYay = util.from_json_string(dictionaryYayString)
                if name in dictionaryYay:
                    fileIDYay = dictionaryYay[name]
                    if self.storage_server.get(self.username + "/dir_keys/" + fileIDYay) is None:
                        raise IntegrityError()
                    else:
                        EKeysAndSignature = util.from_json_string(self.storage_server.get(self.username + "/dir_keys/" + fileIDYay))
                        EKeys = EKeysAndSignature[0]
                        symmetricKeys = util.from_json_string(self.crypto.asymmetric_decrypt(EKeys, self.private_key))
                        signature = EKeysAndSignature[1]
                        authenticated = self.crypto.asymmetric_verify(EKeys, signature, self.pks.get_public_key(self.username))
                        if authenticated:
                            # encrypt value using symmetricKeys[0]
                            EncryptedValue = self.crypto.symmetric_encrypt(value, symmetricKeys[0], 'AES')
                            # HMAC the (fileID, EncryptedValue) using symmKey2 and SHA256
                            hmac = self.crypto.message_authentication_code(util.to_json_string((fileIDYay, EncryptedValue)), symmetricKeys[1], 'SHA256')
                            # put <username>/files/fileID and (E(value), HMAC(fileID, E(value)))
                            self.storage_server.put(self.username + "/files/" + fileIDYay, util.to_json_string((EncryptedValue, hmac)))
                        else:
                            raise IntegrityError()
                else:
                    # generate symmetric keys (encryption, HMAC)
                    symmKey1 = self.crypto.get_random_bytes(16)
                    symmKey2 = self.crypto.get_random_bytes(16)
                    # get user's public key
                    userPublicKey = self.pks.get_public_key(self.username)
                    symmKeys = (symmKey1, symmKey2)
                    # asymmetric encrypt both symmetric keys using user's public key
                    encryptionOfSymmKeys = self.crypto.asymmetric_encrypt(util.to_json_string(symmKeys), userPublicKey)
                    # sign the asymmetric encrypt
                    signedEncryptionOfSymmKeys = self.crypto.asymmetric_sign(encryptionOfSymmKeys, self.private_key)
                    # generate file ID
                    fileID = self.crypto.get_random_bytes(16)
                    # put <username>/dir_keys and AE((symmKey1, symmKey2)), Sign(AE((symmKey1, symmKey2))) to server
                    self.storage_server.put(self.username + "/dir_keys/" + fileID, util.to_json_string((encryptionOfSymmKeys, signedEncryptionOfSymmKeys)))
                    dictionaryYay[name] = fileID
                    # encrypt dictionary using symmKeysYay
                    encryptedDictionary = self.crypto.symmetric_encrypt(util.to_json_string(dictionaryYay), symmKeysYay, 'AES')
                    # put <username>/directory and SE({name : fileID}), E(symmKey1, symmKey2) to server
                    self.storage_server.put(self.username + "/directory", util.to_json_string((encryptedDictionary, ESymms)))
                    # encrypt value using symmKey1
                    EncryptedValue = self.crypto.symmetric_encrypt(value, symmKey1, 'AES')
                    # HMAC the (fileID, EncryptedValue) using symmKey2 and SHA256
                    hmac = self.crypto.message_authentication_code(util.to_json_string((fileID, EncryptedValue)), symmKey2, 'SHA256')
                    # put <username>/files/fileID and (E(value), HMAC(fileID, E(value)))
                    self.storage_server.put(self.username + "/files/" + fileID, util.to_json_string((EncryptedValue, hmac)))
            else:
                # generate symmetric keys (encryption, HMAC)
                symmKey1 = self.crypto.get_random_bytes(16)
                symmKey2 = self.crypto.get_random_bytes(16)
                # get user's public key
                userPublicKey = self.pks.get_public_key(self.username)
                symmKeys = (symmKey1, symmKey2)
                # asymmetric encrypt both symmetric keys using user's public key
                encryptionOfSymmKeys = self.crypto.asymmetric_encrypt(util.to_json_string(symmKeys), userPublicKey)
                # sign the asymmetric encrypt
                signedEncryptionOfSymmKeys = self.crypto.asymmetric_sign(encryptionOfSymmKeys, self.private_key)
                # generate file ID
                fileID = self.crypto.get_random_bytes(16)
                # put <username>/dir_keys and AE((symmKey1, symmKey2)), Sign(AE((symmKey1, symmKey2))) to server
                self.storage_server.put(self.username + "/dir_keys/" + fileID, util.to_json_string((encryptionOfSymmKeys, signedEncryptionOfSymmKeys)))


                # ownerDictionary mapping fileID to owner (for sharing)
                ownerDictionary = {fileID : self.username}
                symmKey3 = self.crypto.get_random_bytes(16)
                hmacOfOwnerDictionary = self.crypto.message_authentication_code(util.to_json_string(ownerDictionary), symmKey3, 'SHA256')
                self.storage_server.put("owner/" + fileID, util.to_json_string((ownerDictionary, hmacOfOwnerDictionary)))



                # shared list to keep track of who shared to who

                sharedDictionary = {self.username : []}
                hmacOfSharedDictionary = self.crypto.message_authentication_code(util.to_json_string(sharedDictionary), symmKey1, 'SHA256')
                self.storage_server.put("shared/" + fileID, util.to_json_string((sharedDictionary, hmacOfSharedDictionary)))



                # dictionary mapping file name to file ID
                dictionary = {name : fileID}
                dictionaryKey = self.crypto.get_random_bytes(16)
                # encrypt dictionary using dictionaryKey
                encryptedDictionary = self.crypto.symmetric_encrypt(util.to_json_string(dictionary), dictionaryKey, 'AES')
                encryptionOfDictionaryKey = self.crypto.asymmetric_encrypt(dictionaryKey, userPublicKey)
                # put <username>/directory and SE({name : fileID}), E(symmKey1, symmKey2) to server
                self.storage_server.put(self.username + "/directory", util.to_json_string((encryptedDictionary, encryptionOfDictionaryKey)))
                # encrypt value using symmKey1
                EncryptedValue = self.crypto.symmetric_encrypt(value, symmKey1, 'AES')
                # HMAC the (fileID, EncryptedValue) using symmKey2 and SHA256
                hmac = self.crypto.message_authentication_code(util.to_json_string((fileID, EncryptedValue)), symmKey2, 'SHA256')
                # put <username>/files/fileID and (E(value), HMAC(fileID, E(value)))
                self.storage_server.put(self.username + "/files/" + fileID, util.to_json_string((EncryptedValue, hmac)))
        except (TypeError, ValueError, CryptoError):
            raise IntegrityError()

        # uid = self.crypto.cryptographic_hash(self.resolve(path_join(self.username, name)), "SHA256")
        # symmetric_key = self.crypto.get_random_bytes(32)
        # try:
        #     asymmetric_key = self.crypto.asymmetric_encrypt(symmetric_key, self.private_key.publickey())
        # except:
        #     raise IntegrityError()
        # if self.storage_server.get(self.username) is not None:
        #     asymmetric_key = self.storage_server.get(self.username)
        #     try:
        #         symmetric_key = self.crypto.asymmetric_decrypt(asymmetric_key, self.private_key)
        #     except:
        #         raise IntegrityError()
        # else:
        #     self.storage_server.put(self.username, asymmetric_key)
        # try:
        #     encrypted_name = self.crypto.symmetric_encrypt(uid, symmetric_key, 'AES')
        #     encrypted_name = util.to_json_string(encrypted_name)
        # except:
        #     raise IntegrityError()
        # try:
        #     value = self.crypto.symmetric_encrypt(value, symmetric_key, 'AES')
        # except:
        #     raise IntegrityError()
        # self.storage_server.put(encrypted_name, value)
        # raise NotImplementedError

    def download(self, name):
        # Replace with your implementation
        try:
            # check if storage_server has directory
            if self.storage_server.get(self.username + "/directory") is None:
                return None
            else:
                # get the encrypted dictionary and encrypted key for the dictionary (E({name : fileID}), E(dictionaryKey))
                encryptedDictionaryAndEncryptedDictionaryKey = util.from_json_string(self.storage_server.get(self.username + "/directory"))
                encryptedDictionary = encryptedDictionaryAndEncryptedDictionaryKey[0]
                encryptedDictionaryKey = encryptedDictionaryAndEncryptedDictionaryKey[1]
                # get dictionary key to decrypt the dictionary
                dictionaryKey = self.crypto.asymmetric_decrypt(encryptedDictionaryKey, self.private_key)
                # decrypt the dictionary
                dictionaryString = self.crypto.symmetric_decrypt(encryptedDictionary, dictionaryKey, 'AES')
                dictionary = util.from_json_string(dictionaryString)
                if name not in dictionary:
                    return None
                else:
                    fileID = dictionary[name]
                    if self.storage_server.get(self.username + "/dir_keys/" + fileID) is None:
                        raise IntegrityError()
                    else:
                        # getting encrypted symmetric keys and signature
                        encryptedKeysAndSignature = util.from_json_string(self.storage_server.get(self.username + "/dir_keys/" + fileID))
                        encryptedKeys = encryptedKeysAndSignature[0]
                        signedEncryptedKeys = encryptedKeysAndSignature[1]
                        # checking the signature
                        validated = self.crypto.asymmetric_verify(encryptedKeys, signedEncryptedKeys, self.pks.get_public_key(self.username))
                        if validated:
                            # decrypt the symmetric keys
                            validatedSymmetricKeys = util.from_json_string(self.crypto.asymmetric_decrypt(encryptedKeys, self.private_key))
                            encryptionKey = validatedSymmetricKeys[0]
                            hmacKey = validatedSymmetricKeys[1]
                            if self.storage_server.get(self.username + "/files/" + fileID) is None:
                                raise IntegrityError()
                            else:
                                encryptedValueAndHMAC = util.from_json_string(self.storage_server.get(self.username + "/files/" + fileID))
                                encryptedValue = encryptedValueAndHMAC[0]
                                originalHMAC = encryptedValueAndHMAC[1]
                                # generate new HMAC to check with original HMAC
                                newHMAC = self.crypto.message_authentication_code(util.to_json_string((fileID, encryptedValue)), hmacKey, 'SHA256')
                                if originalHMAC == newHMAC:
                                    # decrypt and return value
                                    value = self.crypto.symmetric_decrypt(encryptedValue, encryptionKey, 'AES')
                                    return value
                                else:
                                    raise IntegrityError()
                        else:
                            raise IntegrityError()
        except (TypeError, ValueError, CryptoError):
            raise IntegrityError()
        
        # uid = self.crypto.cryptographic_hash(self.resolve(path_join(self.username, name)), "SHA256")
        # if self.storage_server.get(self.username) is None:
        #     return None
        # else: 
        #     asymmetric_key = self.storage_server.get(self.username)
        #     try:
        #         symmetric_key = self.crypto.asymmetric_decrypt(asymmetric_key, self.private_key)
        #     except:
        #         raise IntegrityError()
        # try:
        #     encrypted_name = self.crypto.symmetric_encrypt(uid, symmetric_key, 'AES')
        #     encrypted_name = util.to_json_string(encrypted_name)
        # except:
        #     raise IntegrityError()
        # resp = self.storage_server.get(encrypted_name)
        # try:
        #     resp = self.crypto.symmetric_decrypt(resp, symmetric_key, 'AES')
        # except:
        #     return None
        # if resp is None:
        #     return None
        # return resp
        # raise NotImplementedError

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        try:
            if self.storage_server.get(self.username + "/directory") is None:
                    return None
            else:
                # get the encrypted dictionary and encrypted key for the dictionary (E({name : fileID}), E(dictionaryKey))
                encryptedDictionaryAndEncryptedDictionaryKey = util.from_json_string(self.storage_server.get(self.username + "/directory"))
                encryptedDictionary = encryptedDictionaryAndEncryptedDictionaryKey[0]
                encryptedDictionaryKey = encryptedDictionaryAndEncryptedDictionaryKey[1]
                # get dictionary key to decrypt the dictionary
                dictionaryKey = self.crypto.asymmetric_decrypt(encryptedDictionaryKey, self.private_key)
                # decrypt the dictionary
                dictionaryString = self.crypto.symmetric_decrypt(encryptedDictionary, dictionaryKey, 'AES')
                dictionary = util.from_json_string(dictionaryString)
                if name not in dictionary:
                    return None
                else:
                    fileID = dictionary[name]
                    if self.storage_server.get(self.username + "/dir_keys/" + fileID) is None:
                        raise IntegrityError()
                    else:
                        # getting encrypted symmetric keys and signature
                        encryptedKeysAndSignature = util.from_json_string(self.storage_server.get(self.username + "/dir_keys/" + fileID))
                        encryptedKeys = encryptedKeysAndSignature[0]
                        signedEncryptedKeys = encryptedKeysAndSignature[1]
                        # checking the signature
                        validated = self.crypto.asymmetric_verify(encryptedKeys, signedEncryptedKeys, self.pks.get_public_key(self.username))
                        if validated:
                            # decrypt the symmetric keys
                            # if self.storage_server.get("owner/" + fileID) is None:
                            #     raise IntegrityError()
                            # else:
                            #     ownerAndStuff = util.from_json_string(self.storage_server.get("owner/" + fileID))
                            #     ownerDic = ownerAndStuff[0]
                            #     if fileID not in ownerDic:
                            #         raise IntegrityError()
                            #     else:
                            #         # person = true owner
                            #         person = ownerDic[fileID]
                            #         if self.storage_server.put("shared/" + fileID) is None:
                            #             raise IntegrityError()
                            #         else:
                            #             sharedStuff = util.from_json_string(self.storage_server.get("shared/" + fileID))
                            #             if person == self.username:
                                            



                            validatedSymmetricKeys = util.from_json_string(self.crypto.asymmetric_decrypt(encryptedKeys, self.private_key))
                            encryptionKey = validatedSymmetricKeys[0]
                            hmacKey = validatedSymmetricKeys[1]
                            message = util.to_json_string((fileID, encryptionKey, hmacKey))
                            encryptedMessage = self.crypto.asymmetric_encrypt(message, self.pks.get_public_key(user))
                            return encryptedMessage
                        else:
                            raise IntegrityError()
        except (TypeError, ValueError, CryptoError):
            raise IntegrityError()

        # key = self.storage_server.get(self.username)
        # symmetric_key = self.crypto.asymmetric_decrypt(key, self.private_key)
        # # rsa = asymmetric_encrypt of key and bob's public key
        # rsa = self.crypto.asymmetric_encrypt(symmetric_key, self.pks.get_public_key(user))
        # return (rsa, name)
        # raise NotImplementedError


    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        decryptedMessage = util.from_json_string(self.crypto.asymmetric_decrypt(message, self.private_key))
        fileID = decryptedMessage[0]
        key1 = decryptedMessage[1]
        key2 = decryptedMessage[2]
        # if no directory yet
        if self.storage_server.get(self.username + "/directory") is not None:
            encryptedDictionaryAndKey = util.from_json_string(self.storage_server.get(self.username + "/directory"))
            enDictionary = encryptedDictionaryAndKey[0]
            enKey = encryptedDictionaryAndKey[1]
            directoryKey = self.crypto.asymmetric_decrypt(enKey, self.private_key)
            dictionary = util.from_json_string(self.crypto.symmetric_decrypt(enDictionary, directoryKey, 'AES'))
            dictionary[newname] = fileID
            decryptedDicKey = self.crypto.asymmetric_decrypt(ESymms, self.private_key)
            encryptedDictionary = self.crypto.symmetric_encrypt(util.to_json_string(dictionary), decryptedDicKey, 'AES')
            self.storage_server.put(self.username + "/directory", util.to_json_string((encryptedDictionary, enKey)))
        else:
            dictionary = {newname : fileID}
            dictionaryKey = self.crypto.get_random_bytes(16)
            encryptedDictionary = self.crypto.symmetric_encrypt(util.to_json_string(dictionary), dictionaryKey, 'AES')
            encryptionOfDictionaryKey = self.crypto.asymmetric_encrypt(dictionaryKey, self.pks.get_public_key(self.username))
            self.storage_server.put(self.username + "/directory", util.to_json_string((encryptedDictionary, encryptionOfDictionaryKey)))
        pubKey = self.pks.get_public_key(self.username)
        symmKeys = (key1, key2)
        encryptionOfSymmKeys = self.crypto.asymmetric_encrypt(util.to_json_string(symmKeys), pubKey)
        signedEncryptionOfSymmKeys = self.crypto.asymmetric_sign(encryptionOfSymmKeys, self.private_key)
        self.storage_server.put(self.username + "/dir_keys/" + fileID, util.to_json_string((encryptionOfSymmKeys, signedEncryptionOfSymmKeys)))





        # if self.storage_server.get(self.username + "/shared") is None:
        #     dictionary = {newname : (message[1], from_username, message[0])}
        # else:
        #     dictionary = self.storage_server.get(self.username + "/shared")
        #     dictionary[newname] = (message[1], from_username, message[0])
        # self.storage_server.put(self.username + "/shared", util.to_json_string(dictionary))


        # my_id = path_join(self.username, newname)
        # self.storage_server.put(my_id, "[POINTER] " + message)
        # raise NotImplementedError


    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)



        # sharename = path_join(self.username, "sharewith", user, name)
        # self.storage_server.delete(sharename)
        raise NotImplementedError

