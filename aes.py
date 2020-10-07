
import argparse
import os
import string
import time

from Crypto.Cipher import AES

def pad(data):
    """
    Pad the provided data to be a multiple of the AES block size, then return the padded data

    @param data
    @return padded: The padded data
    """
    padded = data + (AES.block_size - len(data) % AES.block_size) * chr(AES.block_size - len(data) % AES.block_size)
    return padded


def unpad(data):
    """
    Remove the padding from the provided data, then return the unpadded data

    @param data
    @return unpadded: The unpadded data
    """
    unpadded = data[:-ord(data[len(data)-1:])]
    return unpadded


def encrypt(encMode, keyFile, plaintextFile, ivFile, ciphertextFile, output=True):
    """
    Use AES to encrypt plaintext using a key

    @param encMode: Either "ECB" or "CBC", determines which mode the ciphertext is encrypted with
    @param keyFile: The file from which to read the encryption key
    @param plaintextFile: The file from wich to read the plaintext
    @param ivFile: The file to write the generated iv to
    @param ciphertextFile: The file to write the resulting ciphertext to
    """
    # Read key and plaintext files
    with open(keyFile, "r") as f:
        key = f.read()
    key = bytes.fromhex(key)

    with open(plaintextFile, "r") as f:
        plaintextString = f.read()
    
    plaintextPadded = pad(plaintextString)

    if encMode == "CBC":
        iv = os.urandom(16)
        # Write iv to file
        with open(ivFile, "w") as f:
            f.write(iv.hex())

        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif encMode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        print("Error: Invalid encryption mode.")
        return

    result = cipher.encrypt(plaintextPadded).hex()

    with open(ciphertextFile, "w") as f:
        f.write(result)

    if output:
        print("Ciphertext: " + str(result))


def decrypt(keyFile, ivFile, ciphertextFile, resultFile, output=True):
    """
    Use AES to decrypt ciphertext using a key and iv

    @param keyFile: The file from which to read the encryption key
    @param ivFIle: The file containing the initialization vector
    @param ciphertextFile: The file from wich to read the ciphertext
    @param resultFile: The file to write the resulting plaintext to
    """
    with open(keyFile, "r") as f:
        key = bytes.fromhex(f.read())

    with open(ciphertextFile, "r") as f:
        ciphertext = bytes.fromhex(f.read())

    with open(ivFile, "r") as f:
        iv = bytes.fromhex(f.read())

    
    cipher = AES.new(key, AES.MODE_CBC, iv)

    result = unpad(cipher.decrypt(ciphertext)).decode()

    if output:
        print("Decrypted plaintext: " + str(result))

    with open(resultFile, "w") as f:
        f.write(result)


def keygen(file, output=True):
    """
    Generate a random 256-bit key, then write to a file

    @param file: The output file where the key is written
    """
    key = os.urandom(32)  
    hexKey = key.hex()
    with open(file, "w") as f:
        f.write(hexKey)

    if(output):
        print("Key generated: " + hexKey)


def ECB_CBC_test():
    for i in range(1,6):
        print("ECB encryption run #" + str(i) + ":")
        encrypt("ECB", "./data/key.txt", "./data/plaintext.txt", "./data/iv.txt", "./data/ciphertext.txt")
        print("CBC encryption run #" + str(i) + ":")
        encrypt("CBC", "./data/key.txt", "./data/plaintext.txt", "./data/iv.txt", "./data/ciphertext.txt")
        print()


def CBC_time():
    encTimes = []
    decTimes = []
    for i in range(999):
        start = time.time()
        encrypt("CBC", "./data/key.txt", "./data/plaintext.txt", "./data/iv.txt", "./data/ciphertext.txt", output=False)
        end = time.time()
        encTimes.append(end-start)

        start = time.time()
        decrypt("./data/key.txt", "./data/iv.txt", "./data/ciphertext.txt","./data/result.txt", output=False)
        end = time.time()
        decTimes.append(end-start)
    
    print("1000 AES 256 CBC encryptions and decryptions run.")
    print("Average encryption time: " + str(round((sum(encTimes) / len(encTimes)) * 1000, 4)) + " milliseconds")
    print("Average decryption time: " + str(round((sum(decTimes) / len(decTimes)) * 1000, 4)) + " milliseconds")



# Main function
if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser("Encode plaintext, decode ciphertext, or generate a key.")

    subparsers = parser.add_subparsers(help="Types of operations", dest="command")

    enc_parser = subparsers.add_parser("enc")
    dec_parser = subparsers.add_parser("dec")
    key_parser = subparsers.add_parser("keygen")
    keygentest_parser = subparsers.add_parser("ecbcbctest")
    enctest_parser = subparsers.add_parser("cbctime")

    enc_parser.add_argument("mode", help="Encryption mode (CBC or ECB)")
    enc_parser.add_argument("key", help="Key file")
    enc_parser.add_argument("plaintext", help="Plaintext file")
    enc_parser.add_argument("iv", help="IV output file")
    enc_parser.add_argument("ciphertext", help="Ciphertext output file")

    dec_parser.add_argument("key", help="Key file")
    dec_parser.add_argument("iv", help="IV file")
    dec_parser.add_argument("ciphertext", help="Ciphertext file")
    dec_parser.add_argument("result", help="Result output file")

    key_parser.add_argument("file", help="Output file")

    args = parser.parse_args()

    # Run the chosen function based on passed arguments
    if (args.command == "enc"):
        encrypt(args.mode, args.key, args.plaintext, args.iv, args.ciphertext)
    elif (args.command == "dec"):
        decrypt(args.key, args.iv, args.ciphertext, args.result)
    elif (args.command == "keygen"):
        keygen(args.file)
    elif (args.command == "ecbcbctest"):
        ECB_CBC_test()
    elif (args.command == "cbctime"):
        CBC_time()
