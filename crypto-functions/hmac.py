import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def hash_function(message):
    """
    Compute the SHA-256 hash of the given message.
    
    Parameters:
    - message (bytes): The message to be hashed.
    
    Returns:
    - hash_result (bytes): The resulting hash.
    """
    sha256 = hashlib.sha256()
    sha256.update(message)
    hash_result = sha256.digest()
    
    return hash_result


def encrypt_aes(key, data):
    """
    Encrypt data using AES with the given key.
    
    Parameters:
    - key (bytes): The encryption key (must be 16, 24, or 32 bytes long).
    - data (bytes): The data to encrypt.
    
    Returns:
    - ciphertext (bytes): The encrypted data.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # Prepend the IV for use in decryption

def decrypt_aes(key, data):
    """
    Decrypt data using AES with the given key.
    
    Parameters:
    - key (bytes): The encryption key (must be 16, 24, or 32 bytes long).
    - data (bytes): The data to decrypt (IV + ciphertext).
    
    Returns:
    - plaintext (bytes): The decrypted data.
    """
    iv = data[:AES.block_size]
    ct = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def hash_then_encrypt_hmac(key, message, hash_func, encrypt_func):
    """
    Generate a hash-then-encrypt HMAC.
    
    Parameters:
    - key (bytes): The secret key used for the HMAC.
    - message (bytes): The message to be authenticated.
    - hash_func (function): The hash function to use.
    - encrypt_func (function): The encryption function to use.
    
    Returns:
    - hmac_result (bytes): The resulting HMAC.
    """
    # Compute the hash of the message
    hash_result = hash_func(message)
    
    # Encrypt the hash using the encryption function
    hmac_result = encrypt_func(key, hash_result)
    
    return hmac_result

# Define the hash function wrapper
def hash_func(data):
    return hash_function(data)

# Define the encryption function wrapper
def encrypt_func(key, data):
    return encrypt_aes(key, data)

# Generate the HMAC
hmac_result = hash_then_encrypt_hmac(key, message, hash_func, encrypt_func)
