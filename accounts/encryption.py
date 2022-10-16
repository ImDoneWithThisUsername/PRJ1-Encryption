from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import hashlib

def generate_rsa_key():
   key = RSA.generate(2048)
   return key

def encrypt_rsa_private_key(passphrase: str, rsa_key: RSA.RsaKey) -> tuple[bytes, bytes, bytes]:
   private_key = rsa_key.export_key()
   #Encrypt RSA private key
   #Using AES, passphrase = user input
   ## Get aes private key using hashed passphrase for encryption 
   aes_privatekey = AES.new(hashlib.sha256(passphrase.encode()).digest(), AES.MODE_EAX)
   ## Encrypt RSA private key
   cipherkey, tag = aes_privatekey.encrypt_and_digest(private_key)
   return cipherkey, tag, aes_privatekey.nonce

def write_encrypted_private_key_to_file(cipherkey: bytes, tag: bytes, nonce: bytes, file_path: str):
   file_out = open(file_path, "wb")
   [ file_out.write(x) for x in (nonce, tag, cipherkey) ]
   file_out.close()
   return file_path

def read_encrypted_private_key_from_file(file_path: str):
   file_in = open(file_path, "rb")
   nonce, tag, cipherkey = \
      [ file_in.read(x) for x in (16, 16, -1) ]
   file_in.close()
   return cipherkey, tag, nonce

def decrypt_rsa_private_key(passphrase: str, cipherkey: bytes, tag: bytes, nonce:bytes) -> RSA.RsaKey:
   aes_privatekey = AES.new(hashlib.sha256(passphrase.encode()).digest(), AES.MODE_EAX, nonce)
   private_key = aes_privatekey.decrypt_and_verify(cipherkey, tag)
   return RSA.import_key(private_key)

def encrypt_file(file_path):
   pass

def decrypt_file(file_path):
   pass

if __name__ == '__main__':
   debug = True
   if debug == False:
      exit()
   #RSA generator
   key = RSA.generate(2048)
   # print(type(key))
   private_key = key.export_key()

   #Encrypt RSA private key 
   #Using AES, passphrase = user input
   ## Get aes private key using hashed passphrase for encryption 
   aes_privatekey = AES.new(hashlib.sha256("test passphrase".encode()).digest(), AES.MODE_EAX)
   ## Encrypt RSA private key 
   ciphertext, tag = aes_privatekey.encrypt_and_digest(private_key)
   print(type(ciphertext))
   print(type(tag))
   print(type(aes_privatekey.nonce))
   ## Get aes private key using hashed passphrase for decryption
   cipher_aes = AES.new(hashlib.sha256("test passphrase".encode()).digest(), AES.MODE_EAX, aes_privatekey.nonce)
   ## Decrypt rsa private key
   data = cipher_aes.decrypt_and_verify(ciphertext, tag)
   print(data == private_key)
   #write rsa private key to file
   file_out = open("private.pem", "wb")
   file_out.write(private_key)
   file_out.close()

   #write rsa public key to file
   public_key = key.publickey().export_key()
   file_out = open("receiver.pem", "wb")
   file_out.write(public_key)
   file_out.close()

   data = "I met aliens in UFO. Here is the map.".encode("utf-8")
   file_out = open("encrypted_data.bin", "wb")

   #read public key from file
   recipient_key = RSA.import_key(open("receiver.pem").read())
   #generate aes session key
   session_key = get_random_bytes(16)

   # Encrypt session key with the public RSA key
   cipher_rsa = PKCS1_OAEP.new(recipient_key)
   enc_session_key = cipher_rsa.encrypt(session_key)

   # Encrypt data with the AES session key
   # get key
   cipher_aes = AES.new(session_key, AES.MODE_EAX)
   # encrypt
   ciphertext, tag = cipher_aes.encrypt_and_digest(data)
   # write to file
   [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
   file_out.close()

   ######################################################################################
   # open cipher text
   file_in = open("encrypted_data.bin", "rb")

   # read private key from file
   private_key = RSA.import_key(open("private.pem").read())

   # read from file
   enc_session_key, nonce, tag, ciphertext = \
      [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

   # Decrypt the session key with the private RSA key
   cipher_rsa = PKCS1_OAEP.new(private_key)
   session_key = cipher_rsa.decrypt(enc_session_key)

   # Decrypt the data with the AES session key
   cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
   data = cipher_aes.decrypt_and_verify(ciphertext, tag)
   print(data.decode("utf-8"))
