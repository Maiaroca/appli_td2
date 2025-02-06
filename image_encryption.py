import os
from aes_ecb import myAES_encrypt
from Crypto.Util.Padding import pad

def encrypt_image_ecb(input_body, output_body, key):
    """ Encrypt an image file (PPM body) using AES-ECB """
    with open(input_body, "rb") as f:
        plaintext = f.read()

    plaintext_padded = pad(plaintext, 16)

    # Encrypt block by block
    ciphertext = b""
    for i in range(0, len(plaintext_padded), 16):
        ciphertext += myAES_encrypt(key, plaintext_padded[i:i+16])

    with open(output_body, "wb") as f:
        f.write(ciphertext)

if __name__ == "__main__":
    print("Testing Image Encryption with AES-ECB...")

    key = os.urandom(16)

    # Prepare files (run shell commands beforehand)
    os.system("head -n 3 Tux.ppm > Tux.header")
    os.system("tail -n +4 Tux.ppm > Tux.body")

    encrypt_image_ecb("Tux.body", "Tux.body.ecb", key)

    # Reconstruct encrypted image
    os.system("cat Tux.header Tux.body.ecb > Tux.ecb.ppm")
    print("✅ Encrypted image saved as Tux.ecb.ppm.")
