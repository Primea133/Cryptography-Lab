#!/usr/bin/env python3

import sys
# import this
import base64
import Crypto.Util.number
from Crypto.Util.number import *
#import pwntools



if sys.version_info.major == 2:
    print("You are running Python 2, which is no longer supported. Please update to Python 3.")

ords = [81, 64, 75, 66, 70, 93, 73, 72, 1, 92, 109, 2, 84, 109, 66, 75, 70, 90, 2, 92, 79]
ords1 = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
hex = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
hex1 = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
numbers = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
#array = long_to_bytes(numbers)
word = "label"
#word1 = ["l", "a", "b", "e", "l"]
#word2 = []
#number = 13

print("Here is your flag:")
print("".join(chr(o ^ 0x32) for o in ords))
# print(chr(99),chr(114))
print("".join(chr(o) for o in ords1))
print(bytes.fromhex(hex))
print(base64.b64encode(bytes.fromhex(hex1)))
print(long_to_bytes(numbers))

xored_chars = ''.join(chr(ord(char) ^ 13) for char in word)
print(f"crypto{{{xored_chars}}}")
print("".join(chr(ord(char) ^ 13) for char in word))

#key1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
#key2thing = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
KEY1 = int('a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313', 16)
#print(KEY1)
KEY2_XOR_KEY1 = int('37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e', 16)
KEY3_XOR_KEY2 = int('c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1', 16)
FLAG_XOR_KEYS = int('04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf', 16)
KEY2 = KEY2_XOR_KEY1 ^ KEY1
KEY3 = KEY3_XOR_KEY2 ^ KEY2
flag = FLAG_XOR_KEYS ^ KEY1 ^ KEY3 ^ KEY2
#print(flag)
print(long_to_bytes(flag))

key = '73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d'
KEY = int('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d', 16)
#print(long_to_bytes(KEY))

#print(bytes.fromhex(key))


TEST = KEY ^ 11111111
#print(long_to_bytes(TEST))



def decrypt(ciphertext, key):
    return bytes([char ^ key for char in ciphertext])
for possible_key in range(256):
    decrypted_message = decrypt(bytes.fromhex(key), possible_key)
    if decrypted_message[0] == "c" or decrypted_message[0] == "b":
        print("Key:", possible_key)
        print("Decrypted message:", decrypted_message.decode('utf-8'))



# Given ciphertext in hexadecimal format
ciphertext_hex = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"

# Convert the ciphertext from hexadecimal to bytes
#ciphertext_bytes = bytes.fromhex(ciphertext_hex)

# Function to decrypt the ciphertext with a single-byte key
#def decrypt(ciphertext, key):
    #return bytes([char ^ key for char in ciphertext])

# Try all possible single-byte keys
#for possible_key in range(256):
#    decrypted_message = decrypt(ciphertext_bytes, possible_key)
    # Check if the decrypted message contains only printable ASCII characters
    #if all(chr(byte).isprintable() or chr(byte) in {'\n', '\r', '\t'} for byte in decrypted_message):
        #print("Key:", possible_key)
        #print("Decrypted message:", decrypted_message)


keyf = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
KEYF = int('0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104', 16)

# Given ciphertext
ciphertext_hex = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"

# Convert the ciphertext from hexadecimal to bytes
ciphertext_bytes = bytes.fromhex(ciphertext_hex)

# Function to decrypt the ciphertext with a repeated key
def decrypt(ciphertext, key):
    decrypted = bytes([char ^ key[idx % len(key)] for idx, char in enumerate(ciphertext)])
    return decrypted

# Known parts of the plaintext
known_start = b"crypto{"
known_end = b"}"

# Try all possible keys (from 0x00 to 0xFF)
#for possible_key in range(256):
    # Repeat the possible key to match the length of the ciphertext
    #repeated_key = bytes([possible_key] * len(ciphertext_bytes))
    #decrypted_message = decrypt(ciphertext_bytes, possible_key)#repeated_key)
    #print(repeated_key.hex())
    # Check if the decrypted message contains the flag format
    #if decrypted_message.startswith(b"b'") or decrypted_message.startswith(b'c'): #and decrypted_message.endswith("}"):
        #print("Key:", possible_key)
        #print("Decrypted message:", decrypted_message.decode('utf-8'))

# Given ciphertext
ciphertext_hex = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"

# Convert the ciphertext from hexadecimal to bytes
ciphertext_bytes = bytes.fromhex(ciphertext_hex)

# Function to decrypt the ciphertext with a key
def decrypt(ciphertext, key):
    decrypted = bytes([char ^ key[idx % len(key)] for idx, char in enumerate(ciphertext)])
    return decrypted

# Known parts of the plaintext
known_start = b"crypto{"
known_end = b"}"

# Try to decrypt the message using the known parts of the plaintext
for start_idx in range(len(ciphertext_bytes) - len(known_start) + 1):
    for end_idx in range(start_idx + len(known_start), len(ciphertext_bytes) - len(known_end) + 1):
        possible_flag = known_start + ciphertext_bytes[start_idx:end_idx] + known_end
        # Check if the length of possible_flag is longer than the ciphertext
        if len(possible_flag) > len(ciphertext_bytes):
            continue
        possible_key = bytes([possible_flag[idx - len(known_start)] ^ ciphertext_bytes[start_idx + idx - len(known_start)] for idx in range(len(known_start), len(possible_flag) - len(known_end))])
        decrypted_message = decrypt(ciphertext_bytes, possible_key)
        if decrypted_message.startswith(known_start) and decrypted_message.endswith(known_end):
            print("Key:", possible_key.hex())
            print("Decrypted message:", decrypted_message.decode('utf-8'))

main = int('0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104', 16)
attempt1 = int('6d79584f526b65460007', 16)
attempt2 = int('6d79584f526b6546', 16)
flag1 = main ^ attempt1
flag2 = main ^ attempt2
#print(flag)
#print(long_to_bytes(flag1))
#print(long_to_bytes(flag2))

hex_str1 = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
hex_str2 = "6d79584f526b65460007"

# Convert hexadecimal strings to bytes
bytes1 = bytes.fromhex(hex_str1)
bytes2 = bytes.fromhex(hex_str2)

# Determine the length of the longer input
max_len = max(len(bytes1), len(bytes2))

# XOR the bytes cyclically
result_bytes = bytes([b1 ^ b2 for b1, b2 in zip(bytes1, bytes2 * (max_len // len(bytes2) + 1))])

# Convert the result bytes to characters
result_chars = ''.join(chr(byte) for byte in result_bytes)

print("XOR result:", result_chars)

#print(chr(o) for o in word1)
#print(array.decode('utf-8'))
#print(bytes_to_long(numbers).decode('utf-8'))
""""""