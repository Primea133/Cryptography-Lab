import argparse
import subprocess
import sys
import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

FAIL_CODE = 1

def read_sk(f_sk: str, pwd: str) -> RSA.RsaKey:
    """Read a password protected RSA private key from a file.

    :param f_sk: The file to read the private key from
    :param pwd: The password to decrypt the private key
    :return: an RSA key object
    """
    if f_sk == "" or pwd == "":
        print("Make sure you have added all: private key, password")
        sys.exit(FAIL_CODE)
    
    try:
        with open(f_sk, 'rb') as f:
            key = RSA.import_key(f.read(), passphrase=pwd)
            return key
    except subprocess.CalledProcessError:
        print("Failed to read a password protected RSA private key from the file")
        sys.exit(FAIL_CODE)

def read_pk(f_pk: str) -> RSA.RsaKey:
    """Read an RSA public key from a file.

    :param f_pk: The file to read the public key from
    :return: an RSA key object
    """
    if f_pk == "":
        print("Make sure you have added all: public key")
        sys.exit(FAIL_CODE)

    try:
        with open(f_pk, 'rb') as f:
            key = RSA.import_key(f.read())
            return key
    except subprocess.CalledProcessError:
        print("Failed to read the RSA public key from the file")
        sys.exit(FAIL_CODE)

def gen_priv_openssl(f_out: str, pwd: str) -> None:
    """Generate and export an RSA private key using OpenSSL.

    The private key is stored in PEM format and encrypted with AES-256 in
    CBC mode and using PKCS#8 format.

    :param f_out: The file to store the private key in
    :param pwd: The password to use for encrypting the private key
    :raises subprocess.CalledProcessError: Invoking OpenSSL failed
    """
    if f_out == "" or pwd == "":
        print("Make sure you have added all: f_output, password")
        sys.exit(FAIL_CODE)
    
    try:
        subprocess.run(['C:\\Program Files\\Git\\usr\\bin\\openssl.exe', 'genpkey', '-algorithm', 'RSA', '-out', f_out, '-aes256', '-pass', 'pass:' + pwd, '-quiet'])
    except subprocess.CalledProcessError:
        print("Failed to generate the private key with OpenSSL")
        sys.exit(FAIL_CODE)

def gen_pub_openssl(f_in: str, f_out: str, pwd: str) -> None:
    """Derive an RSA public key from a private key using OpenSSL and export it.

    The public key is stored in PEM format.

    :param f_in: The file to read the private key from
    :param f_out: The file to store the public key in
    :param pwd: The password to use for decrypting the private key
    :raises subprocess.CalledProcessError: Invoking OpenSSL failed
    """
    if pwd == "" or f_in == "" or f_out == "":
        print("Make sure you have added all: f_input, f_output, password")
        sys.exit(FAIL_CODE)

    try:
        subprocess.run(['C:\\Program Files\\Git\\usr\\bin\\openssl.exe', 'rsa', '-in', f_in, '-outform', 'PEM', '-pubout', '-out', f_out, '-passin', 'pass:' + pwd])
    except subprocess.CalledProcessError:
        print("Failed to generate the public key with OpenSSL")
        sys.exit(FAIL_CODE)

def encrypt_openssl(f_key: str, f_in: str, f_out: str) -> None:
    """Encrypt a file using OpenSSL.

    :param f_key: The public key file
    :param f_in: The file containing the data to encrypt
    :param f_out: The file to store the ciphertext in
    :raises subprocess.CalledProcessError: Invoking OpenSSL failed
    """
    if f_key == "" or f_in == "" or f_out == "":
        print("Make sure you have added all: key, f_input, f_output")
        sys.exit(FAIL_CODE)

    try:
        subprocess.run(['C:\\Program Files\\Git\\usr\\bin\\openssl.exe', 'pkeyutl', '-encrypt', '-pubin', '-inkey', f_key, '-in', f_in, '-out', f_out, '-pkeyopt', 'rsa_padding_mode:oaep'])
    except subprocess.CalledProcessError:
        print("Failed to encrypt the file with OpenSSL")
        sys.exit(FAIL_CODE)

def decrypt_openssl(f_key: str, f_in: str, f_out: str, pwd: str) -> None:
    """Decrypt a file using OpenSSL.

    :param f_key: The private key file
    :param f_in: The file containing the ciphertext
    :param f_out: The file to store the decrypted data in
    :param pwd: The password to decrypt the private key with
    :raises subprocess.CalledProcessError: Invoking OpenSSL failed
    """
    if f_key == "" or f_in == "" or f_out == "" or pwd == "":
        print("Make sure you have added all: key, f_input, f_output, password")
        sys.exit(FAIL_CODE)
    if f_in == f_out:
        print("Input file cannot be the same as output file")
        sys.exit(FAIL_CODE)

    try:
        subprocess.run(['C:\\Program Files\\Git\\usr\\bin\\openssl.exe', 'pkeyutl', '-decrypt', '-inkey', f_key, '-in', f_in, '-out', f_out, '-passin', 'pass:' + pwd, '-pkeyopt', 'rsa_padding_mode:oaep'])
    except subprocess.CalledProcessError:
        print("Failed to decrypt the file with OpenSSL")
        sys.exit(FAIL_CODE)

def gen_priv_py(f_out: str, pwd: str) -> None:
    """Generate and export an RSA private key with PyCryptodome.

    The private key is stored in PEM format and encrypted with AES-256 in
    CBC mode and using PKCS#8 format.

    :param f_out: The file to store the private key in
    :param pwd: The password to use for encrypting the private key
    """
    if f_out == "" or pwd == "":
        print("Make sure you have added all: f_output, password")
        sys.exit(FAIL_CODE)
    
    key = RSA.generate(3072)
    encrypted_key = key.export_key(passphrase=pwd, pkcs=8, protection="PBKDF2WithHMAC-SHA512AndAES256-CBC", prot_params={'iteration_count':210000}) #iter=210000)# iterations=210000)
    with open(f_out, 'wb') as f:
        f.write(encrypted_key)

def gen_pub_py(f_in: str, f_out: str, pwd: str) -> None:
    """Derive an RSA public key from a private key with PyCryptodome and export it.

    The public key is stored in PEM format.

    :param f_in: The file to read the private key from
    :param f_out: The file to store the public key in
    :param pwd: The password to use for decrypting the private key
    """
    if  f_in == "" or f_out == "" or pwd == "":
        print("Make sure you have added all: f_input, f_output, password")
        sys.exit(FAIL_CODE)
    
    private_key = read_sk(f_in, pwd)
    public_key = private_key.publickey()
    with open(f_out, 'wb') as f:
        f.write(public_key.export_key())

def encrypt_py(f_key: str, f_in: str, f_out: str) -> None:
    """Encrypt a file with PyCryptodome.

    :param f_key: The public key file
    :param f_in: The file containing the data to encrypt
    :param f_out: The file to store the ciphertext in
    """
    if f_key == "" or f_in == "" or f_out == "":
        print("Make sure you have added all: key, f_input, f_output")
        sys.exit(FAIL_CODE)

    recipient_key = read_pk(f_key)
    cipher = PKCS1_OAEP.new(recipient_key)
    with open(f_in, 'rb') as f_in, open(f_out, 'wb') as f_out:
        data = f_in.read()
        encrypted_data = cipher.encrypt(data)
        f_out.write(encrypted_data)

def decrypt_py(f_key: str, f_in: str, f_out: str, pwd: str) -> None:
    """Decrypt a file with PyCryptodome.

    :param f_key: The private key file
    :param f_in: The file containing the ciphertext
    :param f_out: The file to store the decrypted data in
    :param pwd: The password to decrypt the private key with
    """
    if f_key == "" or f_in == "" or f_out == "" or pwd == "":
        print("Make sure you have added all: key, f_input, f_output, password")
        sys.exit(FAIL_CODE)
    if f_in == f_out:
        print("Input file cannot be the same as output file")
        sys.exit(FAIL_CODE)
    
    private_key = read_sk(f_key, pwd)
    cipher = PKCS1_OAEP.new(private_key)
    with open(f_in, 'rb') as f_in, open(f_out, 'wb') as f_out:
        encrypted_data = f_in.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        f_out.write(decrypted_data)

def main(args):
    use_ossl = args.openssl

    if args.action == "genpkey":
        if use_ossl:
            gen_priv_openssl(args.outfile, args.pwd)
        else:
            gen_priv_py(args.outfile, args.pwd)
    elif args.action == "pkey":
        if use_ossl:
            gen_pub_openssl(args.infile, args.outfile, args.pwd)
        else:
            gen_pub_py(args.infile, args.outfile, args.pwd)
    elif args.action == "pkeyutl":
        if args.encrypt:
            if use_ossl:
                encrypt_openssl(args.inkey, args.infile, args.outfile)
            else:
                encrypt_py(args.inkey, args.infile, args.outfile)
        else:
            if use_ossl:
                decrypt_openssl(args.inkey, args.infile, args.outfile, args.pwd)
            else:
                decrypt_py(args.inkey, args.infile, args.outfile, args.pwd)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # It is very messy to emulate CLI parameters similarly to those of OpenSSL.
    sub = parser.add_subparsers(dest="action", help="the task to perform")
    sp_genpkey = sub.add_parser("genpkey")
    sp_pkey = sub.add_parser("pkey")
    sp_pkeyutl = sub.add_parser("pkeyutl")

    for sp in [sp_genpkey, sp_pkey, sp_pkeyutl]:
        sp.add_argument("-x", "--openssl",
                        help="whether to use OpenSSL for the action",
                        action="store_true")
        sp.add_argument("-o", "--out",
                        help="the output file name",
                        dest="outfile", required=True)

    for sp in [sp_pkey, sp_pkeyutl]:
        sp.add_argument("-i", "--in",
                        help="the input file name",
                        dest="infile", required=True)

    for sp in [sp_genpkey, sp_pkey]:
        sp.add_argument("-p", "--pass",
                        help="the private key password",
                        dest="pwd", required=True)

    sp_pkeyutl.add_argument("-k", "--inkey",
                            help="the input key", required=True)
    sp_pkeyutl.add_argument("-p", "--pass",
                            help="the private key password",
                            dest="pwd")
    sp_pkeyutl.add_argument("-e", "--encrypt",
                            help="whether to encrypt instead of decrypting",
                            action="store_true")
    sp_pkeyutl.add_argument("-d", "--decrypt",
                            help="whether to decrypt",
                            action="store_true")

    parsed_args = parser.parse_args()
    if parsed_args.action == "encrypt" and not \
            parsed_args.encrypt and (parsed_args.pwd is None):
        sp_pkeyutl.error("password is required for decryption")

    main(parsed_args)
