from django.test import TestCase
from .encryption import *
from .models import *
# Create your tests here.
class EncryptionTest(TestCase):

    def test_encryption_decryption_private_key_using_cipher_string(self):
        passphrase = "tedfghdfgst"

        key = generate_rsa_key()
        cipherkey, tag, nonce = encrypt_rsa_private_key(passphrase,key.export_key())
        
        cstr = concanate_cipherkey_tag_nonce(cipherkey, tag, nonce)

        cipherkey, tag, nonce = slide_cipherkey_tag_nonce(cstr)
        key_decrypt = decrypt_rsa_private_key(passphrase, cipherkey, tag, nonce)
        
        self.assertEqual(key, RSA.import_key(key_decrypt))

    def test_encryption_decryption_private_key_using_cipher_string_pass_123(self):
        passphrase = "123"

        key = generate_rsa_key()
        cipherkey, tag, nonce = encrypt_rsa_private_key(passphrase,key.export_key())
        
        cstr = concanate_cipherkey_tag_nonce(cipherkey, tag, nonce)

        cipherkey, tag, nonce = slide_cipherkey_tag_nonce(cstr)
        key_decrypt = decrypt_rsa_private_key(passphrase, cipherkey, tag, nonce)
        
        self.assertEqual(key, RSA.import_key(key_decrypt))

    def test_encryption_decryption_private_key_using_cipher_string_pass1_123_pass2_1234(self):
        passphrase1 = "123"
        passphrase2 = "1234"
        
        key = generate_rsa_key()
        cipherkey, tag, nonce = encrypt_rsa_private_key(passphrase1,key.export_key())
        
        cstr = concanate_cipherkey_tag_nonce(cipherkey, tag, nonce)

        cipherkey, tag, nonce = slide_cipherkey_tag_nonce(cstr)
        key_decrypt = decrypt_rsa_private_key(passphrase1, cipherkey, tag, nonce)

        cipherkey, tag, nonce = encrypt_rsa_private_key(passphrase2,key_decrypt)
        key_decrypt2 = decrypt_rsa_private_key(passphrase2, cipherkey, tag, nonce)

        
        self.assertEqual(key, RSA.import_key(key_decrypt))
        self.assertEqual(key, RSA.import_key(key_decrypt2))


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

    def test_binary_field(self):

        passphrase = "123"

        key = generate_rsa_key()
        cipherkey, tag, nonce = encrypt_rsa_private_key(passphrase,key.export_key())
        
        private_key = concanate_cipherkey_tag_nonce(cipherkey, tag, nonce)
        user = CustomUser.objects.create_user(email="m1@gmail.com", password="123", private_key=private_key, passphrase="123")

        cipherkey, tag, nonce = slide_cipherkey_tag_nonce(user.private_key)
        key_decrypt = decrypt_rsa_private_key(user.passphrase, cipherkey, tag, nonce)
        
        self.assertEqual(key, RSA.import_key(key_decrypt))
