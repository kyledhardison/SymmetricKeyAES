
from sys import byteorder
import argparse
import random
import string
import time

def encrypt(keyFile, plaintextFile, ciphertextFile, output=True):
    """
    Use XOR to encrypt plaintext using a key

    @param keyFile: The file from which to read the encryption key
    @param plaintextFile: The file from wich to read the plaintext
    @param ciphertextFile: The file to write the resulting ciphertext to
    """
    with open(keyFile, "r") as f:
        key = f.read()

    with open(plaintextFile, "r") as f:
        plaintextString = f.read()
    
    # Convert each ASCII character to a series of 8 bits and join them all together in to a string
    plaintext = "".join(format(ord(x), "b").zfill(8) for x in plaintextString)

    keyLength = len(key)
    plaintextLength = len(plaintext)

    # Confirm that key lengths are the same, warn and exit if not
    if keyLength != plaintextLength:
        print("ERROR: key length and plain text length are different! Encryption cannot be completed. ")
        print("Key Length: " + str(keyLength) + " bits")
        print("Plain text length: " + str(plaintextLength) + " bits")
        return

    # XOR key and plaintext, then convert result to a bit string, preserving length.
    result = int(key, 2) ^ int(plaintext, 2)
    result = str(format(result, "b").zfill(keyLength))

    with open(ciphertextFile, "w") as f:
        f.write(result)

    if(output):
        print("Plaintext:  " + str(plaintext))
        print("Key:        " + str(key))
        print("Ciphertext: " + str(result))
        print("Output written to " + ciphertextFile)


def decrypt(keyFile, ciphertextFile, resultFile):
    """
    Use XOR to decrypt ciphertext using a key

    @param keyFile: The file from which to read the encryption key
    @param ciphertextFile: The file from wich to read the ciphertext
    @param resultFile: The file to write the resulting plaintext to
    """
    with open(keyFile, "r") as f:
        key = f.read()

    with open(ciphertextFile, "r") as f:
        ciphertextString = f.read()

    keyLength = len(key)
    ciphertextLength = len(ciphertextString)

    # Confirm that key lengths are the same, warn and exit if not
    if keyLength != ciphertextLength:
        print("ERROR: key length and cipher text length are different! Decryption cannot be completed. ")
        print("Key Length: " + str(keyLength) + " bits")
        print("Cipher text length: " + str(ciphertextLength) + " bits")
        return

    # XOR key and ciphertext, then convert result to a bit string, preserving length.
    result = int(key, 2) ^ int(ciphertextString, 2)
    result = str(format(result, "b").zfill(keyLength))

    # Step through the result binary string 8 bits at a time, parsing each to an ascii character.
    resultAscii = ''.join(chr(int(result[i*8:i*8+8],2)) for i in range(len(result)//8))

    print("Key:        " + str(key))
    print("Ciphertext: " + str(ciphertextString))
    print("Plaintext:  " + str(result))
    print("Plaintext in ASCII: " + str(resultAscii))
    print("Output written to " + ciphertextFile)

    with open(resultFile, "w") as f:
        f.write(resultAscii)


def keygen(length, file, output=True):
    """
    Generate a random key of a given length, then write to a file

    @param length: The length of the key, in bits
    @param file: The output file where the key is written
    """
    # Generate random bits
    key = random.getrandbits(length)  

    # Convert key to a string representing the bits, using zfill to preserve length and not drop leading zeroes
    keyBitString = str(format(key, "b").zfill(length)) 

    with open(file, "w") as f:
        f.write(keyBitString)

    if(output):
        print("Key generated: " + keyBitString)
        print("Key written to " + file)


def keygentest():
    """
    Generate 20000 3-bit keys, and calculate the frequency distrobution.
    """
    length = 3
    keys = []
    for _ in range (0, 20000):
        key = str(format(random.getrandbits(length), "b").zfill(length))
        keys.append(key)

    print("20000 3-bit keys generated.")
    avg = 20000/8
    print("Theoretical Average count for each value: " + str(int(avg)))

    keyData = [
        keys.count("000"),
        keys.count("001"),
        keys.count("010"),
        keys.count("011"),
        keys.count("100"),
        keys.count("101"),
        keys.count("110"),
        keys.count("111")
    ]

    keyAvg = [ round(abs(avg-x)/((avg+x)/2)*100, 3) for x in keyData ]

    print("Key Generation Counts:")
    print("000: " + str(keyData[0]) + "  |  Avg. Deviation: " + str(abs(avg-keyData[0])) + "  |  Percent Deviation: " + str(keyAvg[0]) + "%")
    print("001: " + str(keyData[1]) + "  |  Avg. Deviation: " + str(abs(avg-keyData[1])) + "  |  Percent Deviation: " + str(keyAvg[1]) + "%")
    print("010: " + str(keyData[2]) + "  |  Avg. Deviation: " + str(abs(avg-keyData[2])) + "  |  Percent Deviation: " + str(keyAvg[2]) + "%")
    print("011: " + str(keyData[3]) + "  |  Avg. Deviation: " + str(abs(avg-keyData[3])) + "  |  Percent Deviation: " + str(keyAvg[3]) + "%")
    print("100: " + str(keyData[4]) + "  |  Avg. Deviation: " + str(abs(avg-keyData[4])) + "  |  Percent Deviation: " + str(keyAvg[4]) + "%")
    print("101: " + str(keyData[5]) + "  |  Avg. Deviation: " + str(abs(avg-keyData[5])) + "  |  Percent Deviation: " + str(keyAvg[5]) + "%")
    print("110: " + str(keyData[6]) + "  |  Avg. Deviation: " + str(abs(avg-keyData[6])) + "  |  Percent Deviation: " + str(keyAvg[6]) + "%")
    print("111: " + str(keyData[7]) + "  |  Avg. Deviation: " + str(abs(avg-keyData[7])) + "  |  Percent Deviation: " + str(keyAvg[7]) + "%")


def enctest():
    """
    Create 5000 random 128-bit keys and plaintext examples, then measure the average time
    that it takes to encrypt each example.
    """
    times = []

    for _ in range(0, 5000):
        # Generate a random key and plaintext for testing purposes
        keygen(128, "./data/testkey.txt", output=False)

        with open("./data/testplaintext.txt", "w") as f:
            f.write(''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=16)))

        # With the generated test values, run the encryption function and time how long it takes to complete
        start = time.time()
        encrypt("./data/testkey.txt", "./data/testplaintext.txt", "./data/testciphertext.txt", output=False)
        end = time.time()
        times.append(end-start)

    # Calculate and print the average running time, in milliseconds
    print("5000 128-bit encryptions run.")
    print("Average running time: " + str(round((sum(times) / len(times)) * 1000, 4)) + " milliseconds")


# Main function
if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser("Encode plaintext, decode ciphertext, or generate a key.")

    subparsers = parser.add_subparsers(help="Types of operations", dest="command")

    enc_parser = subparsers.add_parser("enc")
    dec_parser = subparsers.add_parser("dec")
    key_parser = subparsers.add_parser("keygen")
    keygentest_parser = subparsers.add_parser("keygentest")
    enctest_parser = subparsers.add_parser("enctest")


    enc_parser.add_argument("key", help="Key file")
    enc_parser.add_argument("plaintext", help="Plaintext file")
    enc_parser.add_argument("ciphertext", help="Ciphertext output file")

    dec_parser.add_argument("key", help="Key file")
    dec_parser.add_argument("ciphertext", help="Ciphertext file")
    dec_parser.add_argument("result", help="Result output file")

    key_parser.add_argument("length", help="Bit length of key", type=int, choices=range(1, 129),
                            metavar="{1-128}")
    key_parser.add_argument("file", help="Output file")

    args = parser.parse_args()

    # Run the chosen function based on passed arguments
    if (args.command == "enc"):
        encrypt(args.key, args.plaintext, args.ciphertext)
    elif (args.command == "dec"):
        decrypt(args.key, args.ciphertext, args.result)
    elif (args.command == "keygen"):
        keygen(args.length, args.file)
    elif (args.command == "keygentest"):
        keygentest()
    elif (args.command == "enctest"):
        enctest()
