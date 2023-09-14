#!/usr/bin/env python3

# Run me like this:
# $ python3 len_ext_attack.py https://project1.eecs388.org/evankash/lengthextension/api?token=d38a806b56562d26fd6789acb86a32a685cb42aecd875163b4e7d906e615522c&command=SprinklersPowerOn
# or select "Length Extension" from the VS Code debugger

import sys
from urllib.parse import quote
from pysha256 import sha256, padding


class URL:
    def __init__(self, url: str):
        # prefix is the slice of the URL from "https://" to "token=", inclusive.
        self.prefix = url[:url.find('=') + 1]
        self.token = url[url.find('=') + 1:url.find('&')]
        # suffix starts at the first "command=" and goes to the end of the URL
        self.suffix = url[url.find('&') + 1:]

    def __str__(self) -> str:
        return f'{self.prefix}{self.token}&{self.suffix}'

    def __repr__(self) -> str:
        return f'{type(self).__name__}({str(self).__repr__()})'


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} URL_TO_EXTEND", file=sys.stderr)
        sys.exit(-1)

    url = URL(sys.argv[1])

    #
    # TODO: Modify the URL
    #
    secret_password = "password" #8-byte password
    extension = "&command=UnlockSafes"
    raw_padding = padding(len(secret_password + url.suffix))
    bytes_consumed = 8 + len(url.suffix) + len(padding(len(url.suffix)+8))
    h1 = sha256(state= bytes.fromhex(url.token), count= bytes_consumed)
    h1.update(extension.encode())
    url.token = h1.hexdigest()
    url.suffix+= quote(raw_padding)
    url.suffix += "&command=UnlockSafes"
    
    print(url)


if __name__ == '__main__':
    main()
