import os
import json
import base64
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

# CONFIGURATION
SALT_SIZE = 16
KEY_SIZE = 32 # 256 bits
ITERATIONS = 200000 # High iteration count to slow down brute-force attacks

def derive_keys(password, salt):
    """
    Splits the Master Password into TWO separate keys using PBKDF2-SHA512.
    We generate 64 bytes of key material:
    - First 32 bytes -> AES Key (Outer Layer)
    - Last 32 bytes  -> ChaCha20 Key (Inner Layer)
    """
    # We ask for 64 bytes (32 for AES + 32 for ChaCha)
    key_material = PBKDF2(password, salt, dkLen=64, count=ITERATIONS, hmac_hash_module=SHA512)
    
    key_aes = key_material[:32]
    key_chacha = key_material[32:]
    
    return key_aes, key_chacha

def encrypt_casket(data_dict, password):
    """
    Double Encryption Logic:
    1. Inner Layer: ChaCha20-Poly1305
    2. Outer Layer: AES-256-GCM
    """
    # 1. Prepare Data
    json_data = json.dumps(data_dict).encode('utf-8')
    salt = get_random_bytes(SALT_SIZE)
    key_aes, key_chacha = derive_keys(password, salt)

    # --- LAYER 1: INNER (ChaCha20) ---
    cipher_chacha = ChaCha20_Poly1305.new(key=key_chacha)
    nonce_chacha = cipher_chacha.nonce
    ciphertext_inner, tag_chacha = cipher_chacha.encrypt_and_digest(json_data)
    
    # Bundle Layer 1 result
    layer1_bundle = nonce_chacha + tag_chacha + ciphertext_inner

    # --- LAYER 2: OUTER (AES-256) ---
    cipher_aes = AES.new(key_aes, AES.MODE_GCM)
    nonce_aes = cipher_aes.nonce
    ciphertext_outer, tag_aes = cipher_aes.encrypt_and_digest(layer1_bundle)

    # --- FINAL PACKAGING ---
    # Structure: [SALT] + [AES_NONCE] + [AES_TAG] + [ENCRYPTED_BLOB]
    final_blob = salt + nonce_aes + tag_aes + ciphertext_outer
    
    # Return as base64 string so it can be saved to a file easily
    return base64.b64encode(final_blob).decode('utf-8')

def decrypt_casket(token, password):
    """
    Reverses the Double Encryption.
    """
    try:
        raw_blob = base64.b64decode(token)
        
        # Extract metadata (Salt, Nonces, Tags) based on fixed sizes
        # Salt = 16 bytes, Nonce = 16 bytes, Tag = 16 bytes
        salt = raw_blob[:SALT_SIZE]
        nonce_aes = raw_blob[SALT_SIZE:SALT_SIZE+16]
        tag_aes = raw_blob[SALT_SIZE+16:SALT_SIZE+32]
        ciphertext_outer = raw_blob[SALT_SIZE+32:]
        
        # Derive the SAME keys
        key_aes, key_chacha = derive_keys(password, salt)

        # --- UNLOCK LAYER 2: OUTER (AES-256) ---
        cipher_aes = AES.new(key_aes, AES.MODE_GCM, nonce=nonce_aes)
        layer1_bundle = cipher_aes.decrypt_and_verify(ciphertext_outer, tag_aes)

        # Extract Inner Layer metadata
        # ChaCha Nonce is usually 8 or 12 bytes, Poly1305 uses 12 bytes standard in PyCryptodome
        nonce_chacha = layer1_bundle[:12] 
        tag_chacha = layer1_bundle[12:28] # Tag is 16 bytes
        ciphertext_inner = layer1_bundle[28:]

        # --- UNLOCK LAYER 1: INNER (ChaCha20) ---
        cipher_chacha = ChaCha20_Poly1305.new(key=key_chacha, nonce=nonce_chacha)
        json_data = cipher_chacha.decrypt_and_verify(ciphertext_inner, tag_chacha)

        return json.loads(json_data)

    except (ValueError, KeyError) as e:
        # This triggers if Password is wrong OR if data was tampered with
        return None