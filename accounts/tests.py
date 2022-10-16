from django.test import TestCase
from .encryption import *

# Create your tests here.
class EncryptionTest(TestCase):

    def test_encryption_decryption_private_key_using_cipher_string(self):
        passphrase = "tedfghdfgst"

        key = generate_rsa_key()
        cipherkey, tag, nonce = encrypt_rsa_private_key(passphrase,key.export_key())
        cstr = concanate_nonce_tag_cipherkey(cipherkey, tag, nonce)
        cipherkey, tag, nonce = slide_nonce_tag_cipherkey(cstr)
        key_decrypt = decrypt_rsa_private_key(passphrase, cipherkey, tag, nonce)
        
        self.assertEqual(key, RSA.import_key(key_decrypt))

    def test_file_encryption_decryption(self):
        file_path = "test.txt"
        with open(file_path, "rb") as file_in:
            plaintext = file_in.read()

        key = generate_rsa_key()
        ciphertext_path = encrypt_file(file_path, key.publickey().export_key())
        plaintext_path = decrypt_file(ciphertext_path, key.export_key())
        with open(plaintext_path, "rb") as file_in:
            decrypted_text = file_in.read()
        self.assertEqual(file_path, plaintext_path)
        self.assertEqual(plaintext, decrypted_text)