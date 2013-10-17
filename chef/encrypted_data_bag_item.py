from chef.exceptions import ChefUnsupportedEncryptionVersionError, ChefDecryptionError
from Crypto.Cipher import AES

import base64
import chef
import hashlib
import simplejson as json

class EncryptedDataBagItem(chef.DataBagItem):
    SUPPORTED_ENCRYPTION_VERSIONS = (1,)

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

    class Decryptors:
        STRIP_CHARS = (chr(15), chr(12),)

        @staticmethod
        def create_decryptor(key, data):
            return {
                1: EncryptedDataBagItem.Decryptors.DecryptorVersion1(key, data['encrypted_data'], data['iv'])
                }[EncryptedDataBagItem.get_version(data)]

        class DecryptorVersion1:
            AES_MODE = AES.MODE_CBC

            def __init__(self, key, data, iv):
                self.key = hashlib.sha256(key).digest()
                self.data = base64.standard_b64decode(data)
                self.iv = base64.standard_b64decode(iv)
                self.decryptor = AES.new(self.key, self.AES_MODE, self.iv)

            def decrypt(self):
                value = self.decryptor.decrypt(self.data)
                # Strip all the \r and \n characters
                value = value.strip(reduce(lambda x,y: "%s%s" % (x,y), EncryptedDataBagItem.Decryptors.STRIP_CHARS))
                # After decryption we should get a JSON string
                try:
                    value = json.loads(value)
                except ValueError:
                    raise ChefDecryptionError()
                return value['json_wrapper']
