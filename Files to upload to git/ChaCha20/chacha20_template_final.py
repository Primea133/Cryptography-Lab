import argparse

KEYFILE = "key.txt"
PUBFILE = "decryption.txt"

from base64 import b64encode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def main(action: str, i_key: str, f_file: str, d_dir: str):
    with open(f_file, "rb") as f:
        plaintext = f.read()

    if action == "encrypt":
        # Erase decryption.txt data in-case there is some data
        with open("decryption.txt", "w") as clear_decryption:
            clear_decryption.write("")

        # Write key to key.txt
        with open("key.txt", "w") as key_file:
            key_file.write(i_key)

        key = i_key.encode('utf-8')

        # Encrypt the pt (plaintext) 5 times
        for i in range(1, 6):
            # Read the contents of the pt (plaintext) file
            with open("plaintext.txt", "rb") as pt_file:
                plaintext = pt_file.read()

            # Set up the encryption and encrypt
            nonce = get_random_bytes(8)
            cipher = ChaCha20.new(key=key, nonce=nonce)
            ct = cipher.encrypt(plaintext)

            # Write the ct (cyphertext) to ct_file
            with open(f"ct-{i}.bin", "wb") as ct_file:
                ct_file.write(ct)
            
            # Append nonces to decryption.txt
            with open("decryption.txt", "a") as decryption_file:
                decryption_file.write(nonce.hex() + "\n")
        print("Successfully encrypted the data!")
        pass

    if action == "decrypt":
        # Read the key from the key file
        with open("key.txt", "r") as key_file:
            initial_key = key_file.read()
            key = initial_key.encode('utf-8')

        # Read the nonces from the decryption file
        with open("decryption.txt", "r") as decryption_file:
            nonces = decryption_file.readlines()

        # Decrypt the ct (cyphertext) 5 times
        for i in range(1, 6):
            # Open the ct files and read the data
            with open(f"ct-{i}.bin", "rb") as ct_files:
                ciphertext = ct_files.read()
            
            # Set up the decryption and decrypt
            nonce = bytes.fromhex(nonces[i-1].strip())
            cipher = ChaCha20.new(key=key, nonce=nonce)


            decrypted = cipher.decrypt(ciphertext)

            assert plaintext == decrypted  # adjust the type if necessary
        print("Successfully decrypted the data!")
        pass

""" If you want to test with custom settings """
# key = "4278b840fb44aaa757c1bf04acbe1a3e"
# main("decrypt", key, "./plaintext.txt", "./")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["encrypt", "decrypt"],
                        help="the action to perform")
    parser.add_argument("key", help="the secret key")
    parser.add_argument("file", help="the file to encrypt/verify against")
    parser.add_argument("dir", help="the directory of ciphertexts")

    args = parser.parse_args()
    main(args.action, args.key, args.file, args.dir)
