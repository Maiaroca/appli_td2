from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def myAES_encrypt(key, m):
    if len(m) != 16:
        return b'Invalid block size'
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.ECB(), backend=None)
    encryptor = cipher.encryptor()
    ct = encryptor.update(m) + encryptor.finalize()
    return ct

def myAES_decrypt(key, m):
    if len(m) != 16:
        return b'Invalid block size'
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.ECB(), backend=None)
    decryptor = cipher.decryptor()
    ct = decryptor.update(m) + decryptor.finalize()
    return ct

if __name__ == "__main__":
    print("Testing AES-ECB implementation...")

    key = os.urandom(16)  # Generate a 16-byte AES key
    plaintext = b"Hello AES ECB!!!"  # Ensure exactly 16 bytes (16 characters)

    if len(plaintext) != 16:
        print(f"Error: Plaintext must be exactly 16 bytes! Current length: {len(plaintext)}")
    else:
        # Encrypt
        ciphertext = myAES_encrypt(key, plaintext)
        if ciphertext == b'Invalid block size':
            print("Encryption failed: Invalid block size")
        else:
            print("Ciphertext:", ciphertext.hex())

            # Decrypt
            decrypted_text = myAES_decrypt(key, ciphertext)
            if decrypted_text == b'Invalid block size':
                print("Decryption failed: Invalid block size")
            else:
                print("Decrypted:", decrypted_text)

                # Validate
                assert decrypted_text == plaintext, "Decryption failed!"
                print("AES-ECB encryption/decryption works correctly.")
