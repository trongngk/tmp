from Crypto.Cipher import DES3
from base64 import b64decode

# Given key and cipher
key_b64 = "MjQxOTIwYTMwY2FjMTRkY2FlYzdhMThm"
cipher_text_b64 = "SiAbinu8S77V2x04SaM6NtznSNpW7nUdn9Eq+ZeAOaX4e7ZXGrDnxrrUHGdEIP7Iypx1VQTHQO3yMjG6eyiFxg=="

# Decode the base64 encoded key
key = b64decode(key_b64)

# Decode the base64 encoded cipher text
cipher_text = b64decode(cipher_text_b64)

# Create a DES3 cipher object with the given key in ECB mode
cipher = DES3.new(key, DES3.MODE_ECB)

# Decrypt the cipher text
decrypted_text = cipher.decrypt(cipher_text)

# Remove padding (PKCS5 padding)
pad_len = decrypted_text[-1]
decrypted_text = decrypted_text[:-pad_len]

# Print the decrypted text
print(decrypted_text.decode('utf-8'))
