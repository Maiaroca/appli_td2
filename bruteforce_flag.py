import time
import random

def decrypt_xor_brute_force(cipher_hex, time_range=2592000):  # Last 30 days
    """ Brute-force decrypts XOR-based encryption with timestamp seeding """
    cipher_bytes = bytes.fromhex(cipher_hex)
    current_time = int(time.time())

    print(f"Starting brute force from time {current_time - time_range} to {current_time}")

    log_file = open("bruteforce_results.txt", "w", encoding="utf-8")  # Log all attempts
    attempts = 0

    for t in range(current_time - time_range, current_time + 1):  # Expanding search range
        for delay in range(51):  # Test all possible sleep delays (0-50 sec)
            random.seed(t + delay)
            decrypted_flag = ""

            for b in cipher_bytes:
                decrypted_flag += chr(b ^ random.randint(0, 255))

            log_entry = f"Timestamp {t}, Delay {delay}: {decrypted_flag}\n"
            log_file.write(log_entry)

            if attempts < 50:  # Print first 50 attempts for debugging
                print(f"🔍 Attempt {attempts+1}: {decrypted_flag[:40]}...")  # Show first 40 chars
                attempts += 1

            if "CTF{" in decrypted_flag:  # Stop if flag format is found
                print(f"✅ Flag found at timestamp {t} (delay {delay}): {decrypted_flag}")
                log_file.close()
                return decrypted_flag  

    log_file.close()
    return None

if __name__ == "__main__":
    print("Testing XOR Brute Force Attack...")

    cipher_hex = "c28fc3acc39f596a0cc2912fc2aa5426c282c29bc2b41bc2ab68c2b716c285c28cc391c29ac3aec3a54ac2aac390c3a6c2a1c3961502c3bb4374c3a8c28ac291c38ac3981bc384c38d"
    
    flag = decrypt_xor_brute_force(cipher_hex, time_range=5184000)  # Search last 60 days

    if flag:
        print("✅ Final Flag:", flag)
    else:
        print("❌ Failed to find the flag after extended search.")
