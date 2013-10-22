from chef.exceptions import ChefUnsupportedEncryptionVersionError, ChefDecryptionError
from Crypto.Cipher import AES

import hmac
import base64
import chef
import hashlib
import simplejson as json

class EncryptedDataBagItem(chef.DataBagItem):
    SUPPORTED_ENCRYPTION_VERSIONS = (1,2)

    def __getitem__(self, key):
        if key == 'id':
            return self.raw_data[key]
        else:
            return EncryptedDataBagItem.Decryptors.create_decryptor(self.api.encryption_key, self.raw_data[key]).decrypt()

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

    class Decryptors(object):
        AES_MODE = AES.MODE_CBC
        STRIP_CHARS =  map(chr,range(0,31))

        @staticmethod
        def create_decryptor(key, data):
            return {
                1: EncryptedDataBagItem.Decryptors.DecryptorVersion1(key, data['encrypted_data'], data['iv']),
                2: EncryptedDataBagItem.Decryptors.DecryptorVersion2(key, data['encrypted_data'], data['iv'], data['hmac'])
                }[EncryptedDataBagItem.get_version(data)]

        class DecryptorVersion1(object):
            def __init__(self, key, data, iv):
                self.key = hashlib.sha256(key).digest()
                self.data = base64.standard_b64decode(data)
                self.iv = base64.standard_b64decode(iv)
                self.decryptor = AES.new(self.key, EncryptedDataBagItem.Decryptors.AES_MODE, self.iv)

            def decrypt(self):
                value = self.decryptor.decrypt(self.data)
                # Strip all the whitespace and sequence controll characters
                value = value.strip(reduce(lambda x,y: "%s%s" % (x,y), EncryptedDataBagItem.Decryptors.STRIP_CHARS))
                # After decryption we should get a JSON string
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

