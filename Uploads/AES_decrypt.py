from Crypto.Cipher import AES

ciphertext=b'v10\x8a\x84\xd44\x96\x10\x18\x8f\x93\tiJ\xe7\xe9W\xbd1\xf8QQY\x89\x03%.\xbb\xb9\xd2\xbb\x86\xaaM\xb8u\xcd'
secret_key=b'O\x86\x8e\xf0L\x84\xdc\xdf&\x0e\x11}&m\x03\n\x1a\x82W\xe5b\xd8"\xf0\xc4V\x1aN\xeep*#'

try: 
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
        decrypted_pass = cipher.decrypt(encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        print(decrypted_pass)
except Exception as e:
        print("Chrome < 80")







        