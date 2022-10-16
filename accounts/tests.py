from django.test import TestCase
from . import encryption

# Create your tests here.
class EncryptionTest(TestCase):

    def test_encryption_decryption_private_key_using_cipher_string(self):
        passphrase = "tedfghdfgst"

        key = encryption.generate_rsa_key()
        cipherkey, tag, nonce = encryption.encrypt_rsa_private_key(passphrase,key.export_key())
        cstr = encryption.concanate_nonce_tag_cipherkey(cipherkey, tag, nonce)
        cipherkey, tag, nonce = encryption.slide_nonce_tag_cipherkey(cstr)
        key_decrypt = encryption.decrypt_rsa_private_key(passphrase, cipherkey, tag, nonce)
        
        self.assertEqual(key, key_decrypt)