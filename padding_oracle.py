#!/usr/bin/env python3

# Run me like this:
# $ python3 padding_oracle.py "https://project1.eecs388.org/uniqname/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
from typing import Dict, List

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue

def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)
    
    # Break the message into blocks

    numBlocks = int(len(message) / 16)
    cypherBlocks = []

    for i in range(numBlocks): # Finds the correct ranges to break up the blocks

        j = i * 16
        k = j + 16

        cypherBlocks.append(message[j:k])

    solvedBlocks = []

    # Should be numBlocks - 1 (Doing this project for every block)
    for current_block in range(1):

        incoming_block = bytearray(cypherBlocks[current_block])
        current_block = bytearray(cypherBlocks[current_block + 1])
        knownBytes = []

        for current_byte in range(4): # Should be 16 (Do this to every byte)

            testReq = []

            for z in range(current_byte): # Part i'm confused with, don't know what to XOR

                incoming_block[15 - z] = knownBytes[z] ^ (current_byte + 2) # Finding the reverse engineered value we want in our edited cyphertext

            for j in range(256): # Creates 256 messages that change only the byte we are focused on

                incoming_block[15 - current_byte] = j # The byte we need to change

                temp = incoming_block + current_block

                testReq.append(bytes(temp))

            retJson = oracle(oracle_url, testReq) # Sends request to oracle

            byteVal = 0 # If output value is negative a invalid_mac was not found

            for j in range(256):

                check = retJson[j]

                if check["status"] == "invalid_mac":

                    byteVal = j
                    print("Valid")

            knownBytes.append(byteVal ^ current_byte) # Adds decrypted byte to known bytes
            print(knownBytes)

        solvedBlocks.append(knownBytes)

    decrypted = "TODO"
    print(decrypted)


if __name__ == '__main__':
    main()
