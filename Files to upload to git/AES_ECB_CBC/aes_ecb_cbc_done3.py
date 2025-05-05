import argparse

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = AES.block_size

def pad_pkcs(msg: bytes, bl: int = BLOCK_SIZE) -> bytes:
    pad_amount = bl - len(msg) % bl
    return msg + bytes([pad_amount] * pad_amount)
    """Pad a message to a multiple of the block length following PKCS#7.

    :param msg: The message to pad
    :param bl: The block length
    :return: the padded message
    """
    pass


def unpad_pkcs(padded: bytes, bl: int = BLOCK_SIZE) -> bytes:
    pad_amount = padded[-1]
    return padded[:-pad_amount]
    """Remove PKCS#7 message padding.

    :param padded: The padded message
    :param bl: The block length
    :return: the unpadded message
    """
    pass

def xor_bytes(a: bytes, b: bytes) -> bytes:
    # Warning! Does not check whether the lengths are the same.
    return bytes(l ^ r for (l, r) in zip(a, b))

def encrypt(msg: bytes, key: bytes, iv: bytes = None) -> bytes:
    
    if iv:
        # Found IV and changing IV size to match block size
        iv = iv[:BLOCK_SIZE]
    else:
        # Did not find/get IV
        iv = get_random_bytes(BLOCK_SIZE)

    # Prep for encryption
    cipher_ECB = AES.new(key, AES.MODE_ECB)
    padded_msg = pad_pkcs(msg)
    ct = b''
    initial_block = iv

    # Encrypting block by block, starting from the first
    for i in range(0, len(padded_msg), BLOCK_SIZE):
        block = padded_msg[i:i + BLOCK_SIZE]
        xored_block = xor_bytes(block, initial_block)
        
        en_block = cipher_ECB.encrypt(xored_block)
        ct += en_block
        initial_block = en_block

    return iv + ct
    
    """ Previous version:
    if iv:
        # Found IV
        # if len(iv) != BLOCK_SIZE:
            # Changed IV size to match block size from, len(iv), to, BLOCK_SIZE)
        aes_object = AES.new(key, AES.MODE_CBC, iv[:BLOCK_SIZE])
        en_msg = aes_object.encrypt(pad_pkcs(msg))
        return iv + en_msg
    # Did not find/get IV
    iv = get_random_bytes(BLOCK_SIZE)
    aes_object = AES.new(key, AES.MODE_CBC, iv)
    en_msg = aes_object.encrypt(pad_pkcs(msg))
    return iv + en_msg
    """

    """Encrypt a message in CBC mode.

    If the IV is not provided, generate a random IV.
    :param msg: The message to encrypt
    :param key: The encryption key
    :param iv: The IV used for encryption
    :return: the ciphertext with the IV as the first block
    """
    pass


def decrypt(ct: bytes, key: bytes) -> bytes:
    # Preparing for decryption
    cipher = AES.new(key, AES.MODE_ECB)
    iv = ct[:BLOCK_SIZE]
    ct = ct[BLOCK_SIZE:]

    # Decrypting block by block, starting from the last
    for i in range(0, len(ct), BLOCK_SIZE):
        ct_block = ct[i:i + BLOCK_SIZE]
        if i == 0:
            unxor_pt_block = cipher.decrypt(ct_block)
            pt_block = xor_bytes(unxor_pt_block, iv)
            pt = pt_block
            continue
        unxor_pt_block = cipher.decrypt(ct_block)
        pt_block = xor_bytes(unxor_pt_block, ct[i - BLOCK_SIZE:i])
        pt = pt + pt_block
    return unpad_pkcs(pt)
    """ Previous version:
    aes_object = AES.new(key, AES.MODE_CBC, ct[:BLOCK_SIZE])
    return unpad_pkcs(aes_object.decrypt(ct[BLOCK_SIZE:]))
    """
    """Decrypt a ciphertext in CBC mode.

    :param ct: The encrypted message
    :param key: The decryption key
    :return: the unpadded plaintext
    """
    pass


def encrypt_lib(msg: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt a message using library CBC.

    :param msg: The message to encrypt
    :param key: The encryption key
    :param iv: The IV used for encryption
    :return: the ciphertext with the IV as the first block
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(pad_pkcs(msg))


def decrypt_lib(ct: bytes, key: bytes) -> bytes:
    """Decrypt a ciphertext using library CBC.

    :param ct: The encrypted message
    :param key: The decryption key
    :return: the unpadded plaintext
    """
    cipher = AES.new(key, AES.MODE_CBC, ct[:BLOCK_SIZE])
    return unpad_pkcs(cipher.decrypt(ct)[BLOCK_SIZE:])


def main(i_key: str, i_msg: str, i_iv: str):
    key = bytes.fromhex(i_key)
    try:
        msg = bytes.fromhex(i_msg)
    except:
        msg = bytes.fromhex(i_msg.encode().hex())

    if i_iv and (len(i_iv) >= (BLOCK_SIZE * 2)):
        iv = bytes.fromhex(i_iv)
        ciphertext = encrypt(msg, key, iv[:BLOCK_SIZE])
    else:
        ciphertext = encrypt(msg, key)
    

    check_enc = encrypt_lib(msg, key, ciphertext[:BLOCK_SIZE])
    assert ciphertext == check_enc

    # Do not remove or modify the print statements.
    print("Key:", key.hex())
    print("PT :", msg.hex())
    print("IV :", ciphertext[:BLOCK_SIZE].hex())
    print("CT :", ciphertext[BLOCK_SIZE:].hex())


    decrypted = decrypt(ciphertext, key)
    check_dec = decrypt_lib(ciphertext, key)

    assert decrypted == check_dec
    assert decrypted == msg

""" If you want to manually try with the message.txt or other values for msg (works) """
"""
key = "4278b840fb44aaa757c1bf04acbe1a3e"
iv = "57f02a5c5339daeb0a2908a06ac6393f"
#iv = ""
with open("message.txt", "r") as file:
    file_content = file.read().encode().hex()
main(key, file_content, iv)
#msg = "Hello world"
#  print(type(msg), msg)
#  msg = msg.encode().hex()
#  print(type(msg), msg)
#msg = "3c888bbbb1a8eb9f3e9b87acaad986c466e2f7071c83083b8a557971918850e5"
#main(key, msg, iv)
"""

""""""
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("key", help="the secret key")
    parser.add_argument("message", help="the message to encrypt")
    parser.add_argument("--iv", help="the initialisation vector (optional)")

    args = parser.parse_args()
    main(args.key, args.message, args.iv)
