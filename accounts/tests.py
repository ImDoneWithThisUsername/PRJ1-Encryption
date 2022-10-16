from django.test import TestCase
from . import encryption

# Create your tests here.
class EncryptionTest(TestCase):
    def test_encryption_decryption_private_key(self):
        key = encryption.generate_rsa_key()
        cipherkey, tag, nonce = encryption.encrypt_rsa_private_key("test",key)
        file_path = encryption.write_encrypted_private_key_to_file(cipherkey, tag, nonce, "key.bin")
        cipherkey, tag, nonce = encryption.read_encrypted_private_key_from_file(file_path)
        key_decrypt = encryption.decrypt_rsa_private_key("test", cipherkey, tag, nonce)
        self.assertEqual(key, key_decrypt)