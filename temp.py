#!/usr/bin/python3
# coding: latin-1
blob = """
                to�N@�Zͥ��֚m&jd�]G_�y1�!r"#���Jq���!\����P�&<���'��A�k-6���4W	�1��d�?��h�A8��0g`��ϓ�T� 4��ɛi����5jO�-�<�aȁo�
"""
from hashlib import sha256
temp = sha256(blob.encode("latin-1")).hexdigest()
print(temp)
if temp == "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b" :
    print("Use SHA-256 instead!")
else:
    print("MD5 is perfectly secure!")

