import hashlib

def compute_flag(k1, k2):
    """ Compute the CTF flag using SHA-256 of k1 + k2 """
    return "CTF{" + hashlib.sha256(k1 + k2).hexdigest() + "}"

if __name__ == "__main__":
    print("Testing AES-ECB Double Encryption Flag Recovery...")

    # Example values for k1 and k2
    k1 = b"random1" + b"A"*29
    k2 = b"random2" + b"A"*29

    flag = compute_flag(k1, k2)
    print("✅ Recovered Flag:", flag)
