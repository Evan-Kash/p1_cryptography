#!/usr/bin/python3
# coding: latin-1
blob = """
                to�N@�Zͥ��֚m&jd�]�_�y1�!r"#���Jq���!\��m�P�&<���'���A�k-6���4W	�1��d�?���h�A8��0g`��ϓ�T� 4��ɛid���5jO�-�<��ȁo�
"""
from hashlib import sha256
temp = sha256(blob.encode("latin-1")).hexdigest()
if temp == "de0a6b23945436846adce290742ad23f4a7bc947253294681e1decc4f8077c28" :
    print("Use SHA-256 instead!")
else:
    print("MD5 is perfectly secure!")

