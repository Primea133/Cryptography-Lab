from Crypto.Signature import eddsa
from Crypto.Hash import SHAKE256
from Crypto.PublicKey import ECC
import os

# Generate Ed448 keypair
key = ECC.generate(curve='ed448')

# Export public key
public_key = key.public_key().export_key(format="PEM").encode()

# Export private key
private_key = key.export_key(format="PEM").encode()

# Save private key to file
with open("private_ed448.pem", "wb") as f:
    f.write(private_key)

# Save public key to file (for demonstration purposes)
with open("public_ed448.pem", "wb") as f:
    f.write(public_key)

# Exchange public key with the other party

# Load private key from file
private_key = ECC.import_key(open("private_ed448.pem").read())

# Message to sign
message = b'I give my permission to order two number 9s, a number 9 large, a number 6 with extra dip, a number 7, two number 45s, one with cheese, and a large soda.'

# Save the message to a file
with open("message.txt", "wb") as f:
    f.write(message)

# Hash the message
#hasher = SHAKE256.new(message)

# Sign the message
signer = eddsa.new(private_key, 'rfc8032')
signature = signer.sign(message)

# After signing the message, save the signature to a file
with open("message.sig", "wb") as f:
    f.write(signature)

# Send the signed message and the signature to the other party

# Receive the signed message and the signature from the other party

# Load public key of the other party
# You should exchange public keys beforehand
public_key_other = ECC.import_key(public_key)

# Verify the signature
verifier = eddsa.new(public_key_other, 'rfc8032')
try:
    verifier.verify(message, signature)
    print("The message is authentic")
except ValueError:
    print("The message is not authentic")
