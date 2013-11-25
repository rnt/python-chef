from chef.exceptions import ChefUnsupportedEncryptionVersionError, ChefDecryptionError
from M2Crypto.EVP import Cipher

import os
import hmac
import base64
import chef
import hashlib
import simplejson as json

class EncryptedDataBagItem(chef.DataBagItem):
    SUPPORTED_ENCRYPTION_VERSIONS = (1,2)
    AES_MODE = 'aes_256_cbc'

    def __getitem__(self, key):
        if key == 'id':
            return self.raw_data[key]
        else:
            return EncryptedDataBagItem.Decryptors.create_decryptor(self.api.encryption_key, self.raw_data[key]).decrypt()

    def __setitem__(self, key, value):
        if key == 'id':
            self.raw_data[key] = value
        else:
            self.raw_data[key] = EncryptedDataBagItem.Encryptors.create_encryptor(self.api.encryption_key, value, 1).to_dict()

    @staticmethod
    def get_version(data):
        if data.has_key('version'):
            if data['version'] in EncryptedDataBagItem.SUPPORTED_ENCRYPTION_VERSIONS:
                return data['version']
            else:
                raise ChefUnsupportedEncryptionVersionError(data['version'])
        else:
            # Should be 0 after implementing DecryptorVersion0
            return "1"

    class Encryptors(object):
        @staticmethod
        def create_encryptor(key, data, version):
            try:
                return {
                    1: EncryptedDataBagItem.Encryptors.EncryptorVersion1(key, data)
                    }[version]
            except KeyError:
                raise ChefUnsupportedEncryptionVersionError(version)

        class EncryptorVersion1(object):
            VERSION = 1
            def __init__(self, key, data):
                self.key = hashlib.sha256(key).digest()
                self.data = data
                self.iv = os.urandom(8).encode('hex')
                self.encryptor = Cipher(alg=EncryptedDataBagItem.AES_MODE, key=self.key, iv=self.iv, op=1)
                self.encrypted_data = None

            def encrypt(self):
                if self.encrypted_data is None:
                    data = json.dumps({'json_wrapper': self.data})
                    self.encrypted_data = self.encryptor.update(data) + self.encryptor.final()
                    del self.encryptor
                return self.encrypted_data

            def to_dict(self):
                return {
                        "encrypted_data": base64.standard_b64encode(self.encrypt()),
                        "iv": base64.standard_b64encode(self.iv),
                        "version": self.VERSION,
                        "cipher": "aes-256-cbc"
                        }

    class Decryptors(object):
        STRIP_CHARS = map(chr,range(0,31))

        @staticmethod
        def create_decryptor(key, data):
            version = EncryptedDataBagItem.get_version(data)
            if version == 1:
                return EncryptedDataBagItem.Decryptors.DecryptorVersion1(key, data['encrypted_data'], data['iv'])
            elif version == 2:
                return EncryptedDataBagItem.Decryptors.DecryptorVersion2(key, data['encrypted_data'], data['iv'], data['hmac'])

        class DecryptorVersion1(object):
            def __init__(self, key, data, iv):
                self.key = hashlib.sha256(key).digest()
                self.data = base64.standard_b64decode(data)
                self.iv = base64.standard_b64decode(iv)
                self.decryptor = Cipher(alg=EncryptedDataBagItem.AES_MODE, key=self.key, iv=self.iv, op=0)

            def decrypt(self):
                value = self.decryptor.update(self.data) + self.decryptor.final()
                del self.decryptor
                # Strip all the whitespace and sequence control characters
                value = value.strip(reduce(lambda x,y: "%s%s" % (x,y), EncryptedDataBagItem.Decryptors.STRIP_CHARS))
                # After decryption we should get a string with JSON
                try:
                    value = json.loads(value)
                except ValueError:
                    raise ChefDecryptionError()
                return value['json_wrapper']

        class DecryptorVersion2(DecryptorVersion1):

            def __init__(self, key, data, iv, hmac):
                super(EncryptedDataBagItem.Decryptors.DecryptorVersion2, self).__init__(key, data, iv)
                self.hmac = base64.standard_b64decode(hmac)
                self.encoded_data = data

            def _validate_hmac(self):
                expected_hmac = hmac.new(self.key, self.encoded_data, hashlib.sha256).digest()
                expected_bytes = map(ord, expected_hmac)
                candidate_hmac_bytes = map(ord, self.hmac)
                valid = len(expected_bytes) ^ len(candidate_hmac_bytes)
                index = 0
                for value in expected_bytes:
                    valid |= value ^ candidate_hmac_bytes[index]
                    index += 1
                return valid == 0

            def decrypt(self):
                if self._validate_hmac():
                    return super(EncryptedDataBagItem.Decryptors.DecryptorVersion2, self).decrypt()
                else:
                    raise ChefDecryptionError()

